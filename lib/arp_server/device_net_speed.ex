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
  @min_upload_speed 2_097_152

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc """
  Add a new device and the net speed is spread equally across all devices in the same ip.
  """
  def online(ip, device_id, tcp_pid) do
    GenServer.cast(__MODULE__, {:online, ip, device_id, tcp_pid})
  end

  @doc """
  Remove a device and update net speed.spread
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
  The state value is:
  %{
    timeout: %{"ip" => 1531881682, ...},
    testing: %{"ip" => "device_id", ...},
    queue: [{"ip", "device_id"}, ...],
    "ip": %{
      upload_speed: 0,
      download_speed: 0,
      device_ids: ["device_id", ...]
    }
  }

  Start an interval timer to check whether the net_speed of ip is expired.
  """
  def init(_opts) do
    Process.send_after(__MODULE__, :interval, @interval)

    {:ok, %{timeout: %{}, testing: %{}, queue: []}}
  end

  def handle_cast({:online, ip, device_id, tcp_pid}, %{timeout: timeout, queue: queue} = state) do
    new_state =
      if Map.has_key?(state, ip) do
        data = state[ip]
        device_ids = [device_id | data[:device_ids]]

        if data[:upload_speed] / length(device_ids) >= @min_upload_speed do
          update_device(device_ids, data[:upload_speed], data[:download_speed])

          DeviceProtocol.speed_test_notify(tcp_pid)

          %{state | timeout: Map.delete(timeout, ip)}
          |> Map.put(ip, %{data | device_ids: device_ids})
        else
          %{state | queue: List.insert_at(queue, length(queue), {ip, device_id, tcp_pid})}
          |> start_speed_test()
          |> Map.put(ip, %{data | device_ids: device_ids})
        end
      else
        data = %{
          upload_speed: 0,
          download_speed: 0,
          device_ids: [device_id]
        }

        %{state | queue: List.insert_at(queue, length(queue), {ip, device_id, tcp_pid})}
        |> start_speed_test()
        |> Map.put(ip, data)
      end

    {:noreply, new_state}
  end

  def handle_cast({:offline, ip, device_id}, state) do
    data = state[ip]

    if data do
      testing = state[:testing]
      device_ids = List.delete(data[:device_ids], device_id)
      state = Map.put(state, ip, %{data | device_ids: device_ids})
      update_device(device_ids, data[:upload_speed], data[:download_speed])

      new_state =
        cond do
          Map.has_key?(testing, ip) ->
            state = %{state | testing: Map.delete(testing, ip)}
            state = calc_state(device_ids, data, state, ip)

            # offline device is testing, test next ip
            start_speed_test(state)

          Enum.empty?(device_ids) ->
            timeout = DateTime.utc_now() |> DateTime.to_unix() |> Kernel.+(@speed_timeout)
            %{state | timeout: Map.put(state[:timeout], ip, timeout)}

          true ->
            state
        end

      {:noreply, new_state}
    else
      {:noreply, state}
    end
  end

  def handle_cast({:set, ip, up, down}, state) do
    new_data = %{state[ip] | upload_speed: up, download_speed: down}

    state = %{state | testing: Map.delete(state[:testing], ip)}
    new_state = state |> start_speed_test() |> Map.put(ip, new_data)

    if length(new_data[:device_ids]) > 0 do
      device_ids = new_data[:device_ids]

      update_device(device_ids, up, down)
    end

    {:noreply, new_state}
  end

  @doc """
  Check timeout and delete expired ip.
  """
  def handle_info(:interval, state) do
    now = DateTime.utc_now() |> DateTime.to_unix()

    expired = for {ip, timeout} <- state[:timeout], timeout < now, do: ip
    normal = Map.drop(state[:timeout], expired)

    new_state =
      state
      |> Map.put(:timeout, normal)
      |> Map.drop(expired)

    Process.send_after(__MODULE__, :interval, @interval)

    {:noreply, new_state}
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
  defp start_speed_test(state) do
    if map_size(state[:testing]) < max_testing_device() do
      {next, new_queue} = List.pop_at(state[:queue], 0)

      if next do
        # notify tcp to start speed testing
        {ip, device_id, tcp_pid} = next

        # notify ARP.API.TCP.DeviceProtocol to start test speed
        DeviceProtocol.speed_test(tcp_pid)

        %{state | testing: Map.put(state[:testing], ip, device_id), queue: new_queue}
      else
        %{state | queue: new_queue}
      end
    else
      state
    end
  end

  defp calc_state(device_ids, data, state, ip) do
    cond do
      Enum.empty?(device_ids) && data[:upload_speed] == 0 && data[:download_speed] == 0 ->
        Map.delete(state, ip)

      length(device_ids) > 0 && data[:upload_speed] == 0 && data[:download_speed] == 0 ->
        [hd | _] = device_ids
        queue = List.insert_at(state[:queue], length(state[:queue]), {ip, hd})
        %{state | queue: queue}

      true ->
        state
    end
  end
end
