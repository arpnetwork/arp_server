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

  @cmd_result_success 0

  @timeout 60_000

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
  Send change state msg to device by device id
  """
  def notify_device_state_changed(id, state, session \\ nil, user_ip \\ nil)

  def notify_device_state_changed(id, state, session, user_ip) when is_binary(id) do
    Store.get(id) |> notify_device_state_changed(state, session, user_ip)
  end

  # Send change state msg to device
  def notify_device_state_changed(socket, state, session, user_ip) do
    %{
      id: @cmd_user_request,
      data: %{
        state: state,
        session: session,
        user_ip: user_ip
      }
    }
    |> send_resp(socket)
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
  def terminate(_reason, %{socket: socket}) do
    # Delete device info and close tcp connect
    id = device_id(socket)
    Store.delete(id)
    ARP.DeviceManager.offline(id)
  end

  @doc """
  Reveive protocol data
  """
  def handle_info({:tcp, socket, data}, %{socket: socket} = state) do
    if byte_size(data) > 0 do
      %{id: id} = req = Poison.decode!(data, keys: :atoms!)
      handle_command(id, Map.get(req, :data), socket, state.transport)
    else
      # :heartbeat
    end

    {:noreply, state, @timeout}
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

  # Online request
  defp handle_command(@cmd_online, data, socket, transport) do
    id = data[:id]

    unless Store.has_key?(id) do
      Store.put(id, socket)

      device = struct(ARP.Device, data)
      {:ok, {ip, _}} = :ranch_tcp.peername(socket)
      ip = ip |> Tuple.to_list() |> Enum.join(".")
      device = struct(device, ip: ip)

      case ARP.DeviceManager.online(device) do
        {:ok, _} ->
          online_resp(socket, @cmd_result_success)

        {:error, _reason} ->
          Store.delete(id)
          transport.close(socket)
      end
    else
      transport.close(socket)
    end
  end

  # Connect user notify
  defp handle_command(@cmd_connect_notify, _data, socket, _transport) do
    id = device_id(socket)
    ARP.DeviceManager.use(id)
  end

  # User request timeout notify
  defp handle_command(@cmd_request_timeout_notify, _data, socket, _transport) do
    idle(socket)
  end

  # User use end notify
  defp handle_command(@cmd_use_end_notify, _data, socket, _transport) do
    idle(socket)
  end

  defp idle(socket) do
    id = device_id(socket)

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
    resp = Poison.encode!(resp)
    :ranch_tcp.send(socket, resp)
  end

  # Return device id by socket
  defp device_id(socket) do
    Store.get(socket)
  end
end
