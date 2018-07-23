defmodule ARP.API.TCP.DeviceProtocol do
  @moduledoc """
  tcp device protocol
  """

  alias ARP.API.TCP.Store

  use GenServer

  @protocol_packet 4
  @protocol_type_data 1
  @protocol_type_speed_test 2

  @cmd_online 1
  @cmd_online_resp 2
  @cmd_user_request 3
  @cmd_connect_notify 4
  @cmd_request_timeout_notify 5
  @cmd_use_end_notify 6
  @cmd_dl_speed_notify 7

  @cmd_result_success 0
  @cmd_result_ver_err -1

  @speed_test_data 1
  @speed_test_start 2
  @speed_test_end 3

  @timeout 60_000

  @speed_test_packet_len 2_621_440
  @speed_test_interval 200

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
    :ok = transport.setopts(socket, active: true, packet: @protocol_packet)

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
      <<@protocol_type_data, data::binary>> = data
      %{id: id} = req = Poison.decode!(data, keys: :atoms!)

      state = handle_command(id, Map.get(req, :data), socket, state)

      {:noreply, state, @timeout}
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

  def handle_info(:speed_test, %{socket: socket, transport: transport} = state) do
    :ok = transport.setopts(socket, active: false, packet: :raw)

    # send download speed test data
    pad_data =
      gen_speed_test_data(@speed_test_data, String.pad_trailing("a", @speed_test_packet_len, "a"))

    :ok = :ranch_tcp.send(socket, gen_speed_test_data(@speed_test_start))
    speed_test_send_loop(socket, pad_data, 5)
    :ok = :ranch_tcp.send(socket, gen_speed_test_data(@speed_test_end))

    # receive download speed test result
    {:ok, size} = :ranch_tcp.recv(socket, @protocol_packet, @timeout)
    {:ok, data} = :ranch_tcp.recv(socket, :binary.decode_unsigned(size), @timeout)
    <<@protocol_type_data, data::binary>> = data
    %{id: 7, data: %{dl_speed: dl_speed}} = Poison.decode!(data, keys: :atoms!)

    # upload speed test start
    {:ok, size} = :ranch_tcp.recv(socket, @protocol_packet, @timeout)

    {:ok, <<@protocol_type_speed_test, @speed_test_start>>} =
      :ranch_tcp.recv(socket, :binary.decode_unsigned(size), @timeout)

    start_time = DateTime.utc_now() |> DateTime.to_unix(:millisecond)

    # receive upload speed test data
    {:ok, size} = :ranch_tcp.recv(socket, @protocol_packet, @timeout)
    {:ok, <<@protocol_type_speed_test, @speed_test_data>>} = :ranch_tcp.recv(socket, 2, @timeout)
    size = :binary.decode_unsigned(size) - 2
    speed_test_recv_loop(socket, size)

    # upload speed test end
    {:ok, len} = :ranch_tcp.recv(socket, @protocol_packet, @timeout)

    {:ok, <<@protocol_type_speed_test, @speed_test_end>>} =
      :ranch_tcp.recv(socket, :binary.decode_unsigned(len), @timeout)

    end_time = DateTime.utc_now() |> DateTime.to_unix(:millisecond)
    ul_speed = round(size / (end_time - start_time) * 1000)

    ip = get_ip(socket)
    # set final speed
    ARP.DeviceNetSpeed.set(ip, ul_speed, dl_speed)

    :ok = transport.setopts(socket, active: true, packet: @protocol_packet)

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
      ip = get_ip(socket)
      # set final speed
      ARP.DeviceNetSpeed.set(ip, ul_speed, dl_speed)
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

  defp gen_speed_test_data(proto, data \\ <<>>) do
    protos = <<@protocol_type_speed_test, proto>>
    size = byte_size(protos) + byte_size(data)
    [<<size::32>>, protos, data]
  end

  defp speed_test_send_loop(socket, pad_data, count) do
    :ok = :ranch_tcp.send(socket, pad_data)
    Process.sleep(@speed_test_interval)

    if count > 0 do
      speed_test_send_loop(socket, pad_data, count - 1)
    end
  end

  defp speed_test_recv_loop(socket, size) do
    cond do
      size == 0 ->
        nil

      size >= @speed_test_packet_len ->
        {:ok, data} = :ranch_tcp.recv(socket, @speed_test_packet_len, @timeout)
        Process.sleep(@speed_test_interval)
        speed_test_recv_loop(socket, size - byte_size(data))

      size < @speed_test_packet_len ->
        {:ok, _data} = :ranch_tcp.recv(socket, size, @timeout)
        speed_test_recv_loop(socket, 0)
    end
  end
end
