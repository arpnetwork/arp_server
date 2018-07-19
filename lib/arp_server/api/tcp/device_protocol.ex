defmodule ARP.API.TCP.DeviceProtocol do
  @moduledoc """
  tcp device protocol
  """

  alias ARP.API.TCP.Store

  use GenServer

  @cmd_online 1
  @cmd_online_resp 2
  @cmd_user_request 3
  @cmd_connect_notify 4
  @cmd_request_timeout_notify 5
  @cmd_use_end_notify 6
  @cmd_dl_speed_notify 7

  @cmd_result_success 0
  @cmd_result_ver_err -1

  @timeout 60_000

  @ver "1.0"
  @compatible_ver [@ver]

  @doc false
  def start_link(ref, socket, transport, _opts \\ []) do
    pid =
      :proc_lib.spawn_link(__MODULE__, :init, [
        %{
          ref: ref,
          socket: socket,
          transport: transport
        }
      ])

    {:ok, pid}
  end

  @doc """
  Send user request msg to device
  """
  def user_request(id, session, user_ip) do
    pid = Store.get(id)
    Process.send(pid, {:user_request, session, user_ip}, [])
  end

  @doc """
  Send download speed test msg to device
  """
  def speed_test(id) do
    pid = Store.get(id)
    Process.send(pid, :speed_test, [])
  end

  @doc false
  def init(%{ref: ref, socket: socket, transport: transport} = state) do
    :ok = :ranch.accept_ack(ref)
    :ok = transport.setopts(socket, active: true, packet: 4)

    :gen_server.enter_loop(
      __MODULE__,
      [],
      state,
      @timeout
    )
  end

  @doc false
  def terminate(_reason, %{socket: _socket}) do
    # Delete device info
    id = device_id()
    Store.delete(id)
    ARP.DeviceManager.offline(id)
  end

  @doc """
  Reveive protocol data
  """
  def handle_info({:tcp, socket, data}, %{socket: socket} = state) do
    if byte_size(data) > 0 do
      cond do
        binary_part(data, 0, 1) == <<1>> ->
          %{id: id} =
            req = binary_part(data, 1, byte_size(data) - 1) |> Poison.decode!(keys: :atoms!)

          state = handle_command(id, Map.get(req, :data), socket, state)

          {:noreply, state, @timeout}

        binary_part(data, 0, 2) == <<2, 1>> ->
          # upload speed data
          recv_time = DateTime.utc_now() |> DateTime.to_unix(:millisecond)
          start_time = state.ul_start
          ul_speed = round(byte_size(data) / (recv_time - start_time) * 1000)
          state = Map.put(state, :ul_speed, ul_speed)
          dl_speed = Map.get(state, :dl_speed)

          if dl_speed do
            _ip = get_ip(socket)
            # TODO set final speed
          end

          {:noreply, state, @timeout}

        binary_part(data, 0, 2) == <<2, 2>> ->
          # start upload speed
          start_time = DateTime.utc_now() |> DateTime.to_unix(:millisecond)
          state = Map.put(state, :ul_start, start_time)

          {:noreply, state, @timeout}

        binary_part(data, 0, 2) == <<2, 3>> ->
          # end upload speed
          {:noreply, state, @timeout}

        true ->
          {:noreply, state, @timeout}
      end
    else
      # :heartbeat
      {:noreply, state, @timeout}
    end
  end

  @doc """
  When tcp connect is closed, clear device info
  """
  def handle_info({:tcp_closed, socket}, %{socket: socket} = state) do
    {:stop, :normal, state}
  end

  @doc """
  When tcp connect is error, clear device info
  """
  def handle_info({:tcp_error, socket, _reason}, %{socket: socket} = state) do
    {:stop, :normal, state}
  end

  @doc """
  When tcp connect is timeout, clear device info
  """
  def handle_info(:timeout, state) do
    {:stop, :normal, state}
  end

  def handle_info(:speed_test, %{socket: socket} = state) do
    pad_data = <<2, 1>> |> String.pad_trailing(10_000_000, <<0>>)

    :ok = :ranch_tcp.send(socket, <<2, 2>>)
    :ok = :ranch_tcp.send(socket, pad_data)
    :ranch_tcp.send(socket, <<2, 3>>)

    {:noreply, state}
  end

  def handle_info({:user_request, session, user_ip}, %{socket: socket} = state) do
    %{
      id: @cmd_user_request,
      data: %{
        session: session,
        user_ip: user_ip
      }
    }
    |> send_resp(socket)

    {:noreply, state}
  end

  # Online request
  defp handle_command(@cmd_online, data, socket, state) do
    id = data[:id]
    ver = data[:ver]

    cond do
      !Enum.member?(@compatible_ver, ver) ->
        online_resp(socket, @cmd_result_ver_err)
        state.transport.close(socket)

      !Store.has_key?(id) ->
        Store.put(id, self())
        device = struct(ARP.Device, data)
        device = struct(device, ip: get_ip(socket))

        case ARP.DeviceManager.online(device) do
          {:ok, _} ->
            online_resp(socket, @cmd_result_success)

          {:error, _reason} ->
            Store.delete(id)
            state.transport.close(socket)
        end

      true ->
        state.transport.close(socket)
    end

    state
  end

  # Connect user notify
  defp handle_command(@cmd_connect_notify, _data, _socket, state) do
    id = device_id()
    ARP.DeviceManager.use(id)
    state
  end

  # User request timeout notify
  defp handle_command(@cmd_request_timeout_notify, _data, _socket, state) do
    idle()
    state
  end

  # User use end notify
  defp handle_command(@cmd_use_end_notify, _data, _socket, state) do
    idle()
    state
  end

  # Dl speed notify
  defp handle_command(@cmd_dl_speed_notify, data, socket, state) do
    dl_speed = data[:dl_speed]
    state = Map.put(state, :dl_speed, dl_speed)
    ul_speed = Map.get(state, :ul_speed)

    if ul_speed do
      _ip = get_ip(socket)
      # TODO set final speed
    end

    state
  end

  defp idle() do
    id = device_id()

    ARP.DeviceManager.idle(id)
  end

  # Send online respone to device
  defp online_resp(socket, result) do
    %{
      id: @cmd_online_resp,
      result: result
    }
    |> send_resp(socket)
  end

  defp send_resp(resp, socket) do
    resp = <<1>> <> Poison.encode!(resp)
    :ranch_tcp.send(socket, resp)
  end

  # Return device id
  defp device_id() do
    Store.get(self())
  end

  # Get device ip
  defp get_ip(socket) do
    {:ok, {ip, _}} = :ranch_tcp.peername(socket)
    ip |> Tuple.to_list() |> Enum.join(".")
  end
end
