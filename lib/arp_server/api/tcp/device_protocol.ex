defmodule ARP.API.TCP.DeviceProtocol do
  @moduledoc """
  tcp device protocol
  """

  alias ARP.API.TCP.Store
  alias ARP.Crypto

  use GenServer

  @protocol_packet 4
  @protocol_type_speed_test 1
  @protocol_type_data 2

  @cmd_device_verify 1
  @cmd_device_verify_resp 2
  @cmd_online 3
  @cmd_online_resp 4
  @cmd_dl_speed_report 5
  @cmd_alloc_request 6
  @cmd_alloc_end_notify 7
  @cmd_device_use_end_report 8
  @cmd_speed_notify 9

  @cmd_result_success 0
  @cmd_result_ver_err -1
  @cmd_result_verify_err -2

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
  def user_request(addr, dapp_address, ip, port, price) do
    pid = Store.get(addr)
    Process.send(pid, {:user_request, dapp_address, ip, port, price}, [])
  end

  @doc """
  Send download speed test msg to device
  """
  def speed_test(addr) do
    pid = Store.get(addr)
    Process.send(pid, :speed_test, [])
  end

  @doc """
  Send alloc end notify to device
  """
  def alloc_end(addr, dapp_address) do
    pid = Store.get(addr)
    Process.send(pid, {:alloc_end, dapp_address}, [])
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
    addr = device_addr()
    Store.delete(addr)
    ARP.Device.offline(addr)
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
    pad_data = String.pad_trailing("a", @speed_test_packet_len, "a")
    send_pad_data = gen_speed_test_data(pad_data)

    count = 4
    dl_size = @speed_test_packet_len * count
    calc_data = String.duplicate(pad_data, count)
    calc_hash = :crypto.hash(:md5, calc_data) |> Base.encode16(case: :lower)

    :ok = :ranch_tcp.send(socket, gen_speed_test_data())
    dl_start_time = DateTime.utc_now() |> DateTime.to_unix(:millisecond)
    speed_test_send_loop(socket, send_pad_data, count)
    :ok = :ranch_tcp.send(socket, gen_speed_test_data())

    # receive download speed test result
    {:ok, size} = :ranch_tcp.recv(socket, @protocol_packet, @timeout)
    {:ok, data} = :ranch_tcp.recv(socket, :binary.decode_unsigned(size), @timeout)
    <<@protocol_type_data, data::binary>> = data
    %{id: @cmd_dl_speed_report, data: %{hash: hash}} = Poison.decode!(data, keys: :atoms!)

    if hash == calc_hash do
      dl_end_time = DateTime.utc_now() |> DateTime.to_unix(:millisecond)
      dl_speed = round(dl_size / (dl_end_time - dl_start_time) * 1000)

      # upload speed test start
      {:ok, size} = :ranch_tcp.recv(socket, @protocol_packet, @timeout)

      {:ok, <<@protocol_type_speed_test>>} =
        :ranch_tcp.recv(socket, :binary.decode_unsigned(size), @timeout)

      start_time = DateTime.utc_now() |> DateTime.to_unix(:millisecond)

      # receive upload speed test data
      {:ok, size} = :ranch_tcp.recv(socket, @protocol_packet, @timeout)

      {:ok, <<@protocol_type_speed_test>>} = :ranch_tcp.recv(socket, 1, @timeout)

      size = :binary.decode_unsigned(size) - 1
      speed_test_recv_loop(socket, size)

      # upload speed test end
      {:ok, len} = :ranch_tcp.recv(socket, @protocol_packet, @timeout)

      {:ok, <<@protocol_type_speed_test>>} =
        :ranch_tcp.recv(socket, :binary.decode_unsigned(len), @timeout)

      end_time = DateTime.utc_now() |> DateTime.to_unix(:millisecond)
      ul_speed = round(size / (end_time - start_time) * 1000)

      ip = get_ip(socket)
      # set final speed
      ARP.DeviceNetSpeed.set(ip, ul_speed, dl_speed)

      :ok = transport.setopts(socket, active: true, packet: @protocol_packet)

      speed_notify(socket, ul_speed, dl_speed)
    else
      transport.close(socket)
    end

    {:noreply, state}
  end

  def handle_info({:user_request, dapp_address, ip, port, price}, %{socket: socket} = state) do
    %{
      id: @cmd_alloc_request,
      data: %{
        address: dapp_address,
        ip: ip,
        port: port,
        price: price
      }
    }
    |> send_resp(socket)

    {:noreply, state}
  end

  def handle_info({:alloc_end, dapp_address}, %{socket: socket} = state) do
    %{
      id: @cmd_alloc_end_notify,
      data: %{
        address: dapp_address
      }
    }
    |> send_resp(socket)

    {:noreply, state}
  end

  # Device verify
  defp handle_command(@cmd_device_verify, data, socket, state) do
    salt = data[:salt]
    sign = data[:sign]
    promise = data[:promise]

    {:ok, device_addr} = Crypto.eth_recover(salt, sign)

    # check device_addr valid
    {:ok, %{private_key: private_key, addr: addr}} = ARP.Account.get_info()

    device_bind = ARP.Contract.get_device_bind_info(device_addr)

    if device_bind.server == addr do
      state = Map.put(state, :device_addr, device_addr)

      send_sign = Crypto.eth_sign(salt, private_key)
      device_verify_resp(socket, @cmd_result_success, send_sign)

      # check promise
      if promise != nil do
        promise = Poison.decode!(promise, keys: :atoms!)
        cid = ARP.Utils.decode_hex(promise[:cid])
        amount = ARP.Utils.decode_hex(promise[:amount])

        result =
          check_recover_promise(
            cid,
            addr,
            device_addr,
            amount,
            promise[:sign]
          )

        if result do
          info = ARP.DevicePromise.get(device_addr)

          if info["cid"] == nil || (cid == info["cid"] && amount > info["amount"]) do
            ARP.DevicePromise.set(device_addr, %{
              "cid" => cid,
              "amount" => amount,
              "approval_time" => 0
            })
          end
        end
      end

      state
    else
      device_verify_resp(socket, @cmd_result_verify_err)
      state
    end
  end

  # Online request
  defp handle_command(@cmd_online, data, socket, state) do
    ver = data[:ver]
    device_addr = Map.get(state, :device_addr)
    {:ok, {ip, _}} = :ranch_tcp.peername(socket)

    cond do
      !device_addr ->
        online_resp(socket, @cmd_result_verify_err)
        state.transport.close(socket)

      !Enum.member?(@compatible_ver, ver) ->
        online_resp(socket, @cmd_result_ver_err)
        state.transport.close(socket)

      :error == ARP.Device.check_port(ip, data[:port], data[:port] + 1) ->
        online_resp(socket, @cmd_result_verify_err)
        state.transport.close(socket)

      !Store.has_key?(device_addr) ->
        Store.put(device_addr, self())
        {:ok, %{addr: addr}} = ARP.Account.get_info()
        %{id: id} = ARP.Contract.bank_allowance(addr, device_addr)
        device = struct(ARP.Device, data)
        device = struct(device, %{ip: get_ip(socket), address: device_addr, cid: id})

        case ARP.Device.online(device) do
          {:ok, _} ->
            online_resp(socket, @cmd_result_success)

          {:error, _reason} ->
            Store.delete(device_addr)
            state.transport.close(socket)
        end

      true ->
        state.transport.close(socket)
    end

    state
  end

  # Device use end report
  defp handle_command(@cmd_device_use_end_report, _data, _socket, state) do
    idle()
    state
  end

  defp idle() do
    addr = device_addr()
    ARP.Device.idle(addr)
  end

  # Send online respone to device
  defp online_resp(socket, result) do
    %{
      id: @cmd_online_resp,
      result: result
    }
    |> send_resp(socket)
  end

  # Send device verify response

  defp device_verify_resp(socket, result) do
    data = %{
      id: @cmd_device_verify_resp,
      result: result
    }

    send_resp(data, socket)
  end

  defp device_verify_resp(socket, result, sign) do
    data = %{
      id: @cmd_device_verify_resp,
      result: result,
      data: %{
        sign: sign
      }
    }

    send_resp(data, socket)
  end

  defp speed_notify(socket, upload_speed, download_speed) do
    data = %{
      id: @cmd_speed_notify,
      data: %{
        upload_speed: upload_speed,
        download_speed: download_speed
      }
    }

    send_resp(data, socket)
  end

  defp send_resp(resp, socket) do
    resp = <<@protocol_type_data>> <> Poison.encode!(resp)
    :ranch_tcp.send(socket, resp)
  end

  # Return device address
  defp device_addr() do
    Store.get(self())
  end

  # Get device ip
  defp get_ip(socket) do
    {:ok, {ip, _}} = :ranch_tcp.peername(socket)
    ip |> Tuple.to_list() |> Enum.join(".")
  end

  defp gen_speed_test_data(data \\ <<>>) do
    protos = <<@protocol_type_speed_test>>
    size = byte_size(protos) + byte_size(data)
    [<<size::32>>, protos, data]
  end

  defp speed_test_send_loop(socket, pad_data, count) do
    :ok = :ranch_tcp.send(socket, pad_data)
    Process.sleep(@speed_test_interval)

    if count > 1 do
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

  defp check_recover_promise(cid, server_addr, device_addr, amount, sign) do
    decode_server_addr = server_addr |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    decode_device_addr = device_addr |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    data =
      <<cid::size(256), decode_server_addr::binary-size(20), decode_device_addr::binary-size(20),
        amount::size(256)>>

    {:ok, addr} = Crypto.eth_recover(data, sign)

    if addr == server_addr do
      true
    else
      false
    end
  end
end
