defmodule ARP.DeviceNetSpeed do
  @moduledoc """
  Record the net speed for ip.
  """
  require Logger

  alias ARP.API.TCP.DeviceProtocol
  alias ARP.{Config, DevicePool}

  use GenServer

  @interval 60_000
  @speed_timeout 86_400
  @speed_test_timeout 50_000
  @min_upload_speed 524_288

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc """
  Add a new device and the net speed is equally across all devices in the same ip.
  """
  def online(ip, device_id, tcp_pid) do
    GenServer.cast(__MODULE__, {:online, ip, device_id, tcp_pid})
  end

  @doc """
  Remove a device and update net speed.
  """
  def offline(ip, device_id) do
    GenServer.cast(__MODULE__, {:offline, ip, device_id})
  end

  @doc """
  Set net speed after test.
  """
  def set(ip, up, down) when up > 0 and down > 0 do
    GenServer.cast(__MODULE__, {:set, ip, up, down})
  end

  @doc """
  Get net speed data.
  """
  def get do
    GenServer.call(__MODULE__, :get)
  end

  @doc """
  The state value is:
  %{
    timeout: %{"ip" => 1531881682, ...},
    testing: %{"ip" => {"device_id", tcp_pid, timer}, ...},
    queue: [{"ip", "device_id", tcp_pid}, ...],
    "ip": %{
      upload_speed: 0,
      download_speed: 0,
      device_ids: ["device_id", ...]
    }
  }

  Start an interval timer to check whether the net_speed of ip is expired.
  """
  def init(_opts) do
    Process.send_after(__MODULE__, :check, @interval)

    {:ok, %{timeout: %{}, testing: %{}, queue: []}}
  end

  def handle_cast({:online, ip, device_id, tcp_pid}, %{queue: queue, timeout: timeout} = state) do
    new_state = %{
      state
      | queue: List.insert_at(queue, length(queue), {ip, device_id, tcp_pid}),
        timeout: Map.delete(timeout, ip)
    }

    {:noreply, start_next(new_state)}
  end

  def handle_cast({:offline, ip, device_id}, %{testing: testing, queue: queue} = state) do
    new_state =
      cond do
        Enum.any?(queue, fn {q_ip, q_device_id, _} -> q_ip == ip && q_device_id == device_id end) ->
          # is in queue
          index =
            Enum.find_index(queue, fn {q_ip, q_device_id, _} ->
              q_ip == ip && q_device_id == device_id
            end)

          new_queue = List.delete_at(queue, index)

          %{state | queue: new_queue}

        Map.has_key?(testing, ip) ->
          # is testing
          {{_, _, timer}, new_testing} = Map.pop(testing, ip, nil)
          Process.cancel_timer(timer)
          state = %{state | testing: new_testing}
          start_next(state)

        Map.has_key?(state, ip) ->
          # has tested
          data = state[ip]
          device_ids = List.delete(data[:device_ids], device_id)
          update_device(device_ids, data[:upload_speed], data[:download_speed])
          state = Map.put(state, ip, %{data | device_ids: device_ids})

          if Enum.empty?(device_ids) do
            # no device online, set timeout
            timeout = DateTime.utc_now() |> DateTime.to_unix() |> Kernel.+(@speed_timeout)
            %{state | timeout: Map.put(state[:timeout], ip, timeout)}
          else
            state
          end

        true ->
          state
      end

    {:noreply, new_state}
  end

  def handle_cast({:set, ip, up, down}, state) do
    new_state =
      case Map.pop(state[:testing], ip, nil) do
        {{device_id, tcp_pid, timer}, testing} ->
          Process.cancel_timer(timer)
          state = %{state | testing: testing}

          if up >= @min_upload_speed do
            # speed is ok
            device_ids = [device_id]
            update_device(device_ids, up, down)
            DeviceProtocol.speed_test_notify(tcp_pid, true)
            new_data = %{upload_speed: up, download_speed: down, device_ids: device_ids}
            Map.put(state, ip, new_data)
          else
            # speed is too slow
            DeviceProtocol.speed_test_notify(tcp_pid, false)
            state
          end

        _ ->
          state
      end

    {:noreply, start_next(new_state)}
  end

  def handle_call(:get, _from, state) do
    {:reply, state, state}
  end

  @doc """
  Check timeout and delete expired ip.
  """
  def handle_info(:check, state) do
    now = DateTime.utc_now() |> DateTime.to_unix()

    expired_ips = for {ip, timeout} <- state[:timeout], timeout < now, do: ip

    new_state =
      if Enum.empty?(expired_ips) do
        state
      else
        Logger.info("delete timeout device net speed #{inspect(expired_ips)}")

        new_timeout = Map.drop(state[:timeout], expired_ips)

        state
        |> Map.put(:timeout, new_timeout)
        |> Map.drop(expired_ips)
      end

    Process.send_after(__MODULE__, :check, @interval)

    {:noreply, new_state}
  end

  @doc """
  Speed test timeout
  """
  def handle_info({:speed_test_timeout, ip}, state) do
    new_state =
      case Map.pop(state[:testing], ip, nil) do
        {{device_id, tcp_pid, _timer}, new_testing} ->
          Logger.info("speed test timeout. ip = #{ip}, address = #{device_id}")
          DeviceProtocol.speed_test_notify(tcp_pid, false)
          %{state | testing: new_testing}

        _ ->
          state
      end

    {:noreply, start_next(new_state)}
  end

  defp max_testing_device do
    bandwidth = Config.get(:bandwidth)
    bandwidth |> div(100) |> max(1)
  end

  # Notify Device to update device net speed.
  defp update_device(device_ids, up, down) do
    l = length(device_ids)

    if l > 0 do
      avg_up = round(up / l)
      avg_down = round(down / l)
      DevicePool.update_net_speed(device_ids, avg_up, avg_down)
    end
  end

  # Notify device tcp socket to start test net speed.
  defp start_next(state) do
    if length(state[:queue]) > 0 do
      {ip, device_id, tcp_pid} = List.first(state[:queue])
      data = state[ip]

      cond do
        Map.has_key?(state[:testing], ip) ->
          # other device with same ip is testing, wait
          state

        is_nil(data) ->
          # never tested
          if map_size(state[:testing]) < max_testing_device() do
            # notify ARP.API.TCP.DeviceProtocol to start test speed
            DeviceProtocol.start_speed_test(tcp_pid)

            timer = Process.send_after(self(), {:speed_test_timeout, ip}, @speed_test_timeout)
            new_testing = Map.put(state[:testing], ip, {device_id, tcp_pid, timer})
            {_, new_queue} = List.pop_at(state[:queue], 0)

            state
            |> Map.put(:testing, new_testing)
            |> Map.put(:queue, new_queue)
          else
            # wait
            state
          end

        data[:upload_speed] / (length(data[:device_ids]) + 1) >= @min_upload_speed ->
          # speed is ok
          device_ids = [device_id | data[:device_ids]]
          update_device(device_ids, data[:upload_speed], data[:download_speed])

          Logger.debug(fn ->
            "set net speed ok. ip: #{ip}, up: #{
              data[:upload_speed] / (length(data[:device_ids]) + 1)
            }, down: #{data[:download_speed] / (length(data[:device_ids]) + 1)}"
          end)

          DeviceProtocol.speed_test_notify(tcp_pid, true)
          {_, new_queue} = List.pop_at(state[:queue], 0)

          %{state | queue: new_queue}
          |> Map.put(ip, %{data | device_ids: device_ids})

        true ->
          # speed is too slow
          Logger.debug(fn ->
            "set net speed too slow. ip: #{ip}, up: #{
              data[:upload_speed] / (length(data[:device_ids]) + 1)
            }, down: #{data[:download_speed] / (length(data[:device_ids]) + 1)}"
          end)

          DeviceProtocol.speed_test_notify(tcp_pid, false)
          {_, new_queue} = List.pop_at(state[:queue], 0)

          %{state | queue: new_queue}
      end
    else
      state
    end
  end
end
