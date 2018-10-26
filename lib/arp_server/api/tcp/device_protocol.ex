defmodule ARP.API.TCP.DeviceProtocol do
  @moduledoc """
  tcp device protocol
  """

  alias ARP.{
    Account,
    Config,
    Contract,
    Crypto,
    Device,
    DeviceNetSpeed,
    DevicePool,
    DevicePromise,
    Promise
  }

  require Logger

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
  @cmd_repeat_connect_offline_notify 10

  @cmd_result_success 0
  @cmd_result_ver_err -1
  @cmd_result_verify_err -2
  @cmd_result_port_err -3
  @cmd_result_max_load_err -4
  @cmd_result_speed_test_err -5

  @timeout 60_000
  @speed_timeout 60_000

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
  def user_request(pid, dapp_address, ip, port, price) do
    Process.send(pid, {:user_request, dapp_address, ip, port, price}, [])
  end

  @doc """
  Send download speed test msg to device
  """
  def speed_test(pid) do
    Process.send(pid, :speed_test, [])
  end

  def speed_test_notify(pid, ul_speed, dl_speed) do
    Process.send(pid, {:speed_test_notify, ul_speed, dl_speed}, [])
  end

  @doc """
  Send alloc end notify to device
  """
  def alloc_end(pid, dapp_address) do
    Process.send(pid, {:alloc_end, dapp_address}, [])
  end

  def repeat_connect_offline(pid, addr) do
    GenServer.call(pid, {:repeat_connect_offline, addr}, @speed_timeout)
  end

  @doc false
  def init(%{ref: ref, socket: socket, transport: transport} = state) do
    :ok = :ranch.accept_ack(ref)
    :ok = transport.setopts(socket, active: true, packet: @protocol_packet)

    Logger.info("socket connect." <> inspect(socket))

    :gen_server.enter_loop(
      __MODULE__,
      [],
      state,
      @timeout
    )
  end

  @doc false
  def terminate(reason, %{socket: socket} = state) do
    device_addr = Map.get(state, :device_addr)

    Logger.info(
      "socket disconnect." <> inspect(socket) <> " reason: #{reason}, device addr: #{device_addr}"
    )

    # Delete device info
    with {_, dev} <- DevicePool.get_by_tcp_pid(self()) do
      DeviceNetSpeed.offline(dev.ip, dev.address)
      DevicePool.offline(dev.address)
    end
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
    {:ok, size} = :ranch_tcp.recv(socket, @protocol_packet, @speed_timeout)
    {:ok, data} = :ranch_tcp.recv(socket, :binary.decode_unsigned(size), @speed_timeout)
    <<@protocol_type_data, data::binary>> = data
    %{id: @cmd_dl_speed_report, data: %{hash: hash}} = Poison.decode!(data, keys: :atoms!)

    if hash == calc_hash do
      dl_end_time = DateTime.utc_now() |> DateTime.to_unix(:millisecond)
      dl_speed = round(dl_size / (dl_end_time - dl_start_time) * 1000)

      # upload speed test start
      {:ok, size} = :ranch_tcp.recv(socket, @protocol_packet, @speed_timeout)

      {:ok, <<@protocol_type_speed_test>>} =
        :ranch_tcp.recv(socket, :binary.decode_unsigned(size), @speed_timeout)

      start_time = DateTime.utc_now() |> DateTime.to_unix(:millisecond)

      # receive upload speed test data
      {:ok, size} = :ranch_tcp.recv(socket, @protocol_packet, @speed_timeout)

      {:ok, <<@protocol_type_speed_test>>} = :ranch_tcp.recv(socket, 1, @speed_timeout)

      size = :binary.decode_unsigned(size) - 1
      speed_test_recv_loop(socket, size)

      # upload speed test end
      {:ok, len} = :ranch_tcp.recv(socket, @protocol_packet, @speed_timeout)

      {:ok, <<@protocol_type_speed_test>>} =
        :ranch_tcp.recv(socket, :binary.decode_unsigned(len), @speed_timeout)

      end_time = DateTime.utc_now() |> DateTime.to_unix(:millisecond)
      ul_speed = round(size / (end_time - start_time) * 1000)

      ip = get_ip(socket)
      # set final speed
      DeviceNetSpeed.set(ip, ul_speed, dl_speed)

      :ok = transport.setopts(socket, active: true, packet: @protocol_packet)

      speed_notify(socket, @cmd_result_success, ul_speed, dl_speed)
    else
      speed_notify(socket, @cmd_result_speed_test_err)
      transport.close(socket)
      device_addr = Map.get(state, :device_addr)
      Logger.info("device offline, reason: speed test hash err, device addr: #{device_addr}")
    end

    {:noreply, state}
  rescue
    _err ->
      speed_notify(socket, @cmd_result_speed_test_err)
      Process.sleep(1000)
      device_addr = Map.get(state, :device_addr)
      Logger.info("device offline, reason: speed test err, device addr: #{device_addr}")
      {:stop, :normal, state}
  end

  def handle_info({:speed_test_notify, ul_speed, dl_speed}, %{socket: socket} = state) do
    speed_notify(socket, @cmd_result_success, ul_speed, dl_speed)

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

  def handle_call({:repeat_connect_offline, addr}, _from, %{socket: socket} = state) do
    %{
      id: @cmd_repeat_connect_offline_notify,
      data: %{
        address: addr
      }
    }
    |> send_resp(socket)

    Logger.info("device offline, reason: repeat connect, device addr: #{addr}")

    {:stop, :normal, :ok, state}
  end

  # Device verify
  defp handle_command(@cmd_device_verify, data, socket, state) do
    salt = data[:salt]
    sign = data[:sign]
    promise = data[:promise]

    # check device_addr valid
    private_key = Account.private_key()
    addr = Account.address()

    with {:ok, device_addr} <- Crypto.eth_recover(salt, sign),
         {:ok, %{server: server}} when server == addr <-
           Contract.get_device_bind_info(device_addr) do
      state = Map.put(state, :device_addr, device_addr)

      # check promise
      {:ok, %{id: cid, paid: paid}} = Contract.bank_allowance(addr, device_addr)
      remote_promise = check_remote_promise(promise, cid, addr, device_addr)
      local_promise = DevicePromise.get(device_addr)
      local_promise = check_local_promise(local_promise, cid, addr, device_addr)

      cond do
        cid == 0 ->
          # promise is invalid
          DevicePromise.delete(device_addr)

        remote_promise && (is_nil(local_promise) || local_promise.amount < remote_promise.amount) ->
          # recover device promise when local promise is invalid
          DevicePromise.set(device_addr, remote_promise)

        is_nil(local_promise) && is_nil(remote_promise) ->
          DevicePromise.set(
            device_addr,
            Promise.create(private_key, cid, addr, device_addr, paid)
          )

        true ->
          nil
      end

      send_sign = Crypto.eth_sign(salt, private_key)
      device_verify_resp(socket, @cmd_result_success, send_sign)

      state
    else
      _ ->
        device_verify_resp(socket, @cmd_result_verify_err)
        state
    end
  end

  # Online request
  defp handle_command(@cmd_online, data, socket, state) do
    # compatible
    tcp_port = data[:tcp_port] || data[:port]
    http_port = data[:http_port] || tcp_port + 1
    data = data |> Map.put(:tcp_port, tcp_port) |> Map.put(:http_port, http_port)

    ver = data[:ver]
    device_addr = Map.get(state, :device_addr)
    ip = get_ip(socket)
    host = data[:proxy] || ip

    cond do
      DevicePool.size() >= Config.get(:max_load) ->
        online_resp(socket, @cmd_result_max_load_err)
        state.transport.close(socket)
        Logger.info("online faild, reason: max load err, device addr: #{device_addr}")

      !device_addr ->
        online_resp(socket, @cmd_result_verify_err)
        state.transport.close(socket)
        Logger.info("online faild, reason: device verify err")

      !Enum.member?(@compatible_ver, ver) ->
        online_resp(socket, @cmd_result_ver_err)
        state.transport.close(socket)
        Logger.info("online faild, reason: ver err, device addr: #{device_addr}")

      Enum.all?([data[:tcp_port], data[:http_port]], fn x -> x >= 0 && x <= 65_535 end) == false ->
        online_resp(socket, @cmd_result_port_err)
        state.transport.close(socket)
        Logger.info("online faild, reason: check port err, device addr: #{device_addr}")

      :error == Device.check_port(host |> to_charlist(), data[:tcp_port], data[:http_port]) ->
        online_resp(socket, @cmd_result_port_err)
        state.transport.close(socket)
        Logger.info("online faild, reason: check port err, device addr: #{device_addr}")

      true ->
        addr = Account.address()

        with {:ok, %{id: id}} when id != 0 <- Contract.bank_allowance(addr, device_addr),
             device = struct(ARP.Device, data),
             device =
               struct(device, %{
                 address: device_addr,
                 tcp_pid: self(),
                 ip: host,
                 original_ip: ip,
                 cid: id
               }),
             :ok <- online(device) do
          DeviceNetSpeed.online(ip, device_addr, self())

          online_resp(socket, @cmd_result_success)

          Logger.info("online success, device addr: #{device_addr}")
        else
          _ ->
            online_resp(socket, @cmd_result_verify_err)
            state.transport.close(socket)
            Logger.info("online faild, reason: online err, device addr: #{device_addr}")
        end
    end

    state
  end

  # Device use end report
  defp handle_command(@cmd_device_use_end_report, _data, _socket, state) do
    idle()
    state
  end

  defp online(:ok) do
    :ok
  end

  defp online(:error) do
    :error
  end

  defp online(device) do
    res =
      with :ok <- DevicePool.online(device) do
        :ok
      else
        {:error, :duplicate_address} ->
          with {_, old_dev} <- DevicePool.get(device.address) do
            repeat_connect_offline(old_dev.tcp_pid, device.address)
          end

          device

        _ ->
          :error
      end

    online(res)
  end

  defp idle do
    with {_, dev} <- DevicePool.get_by_tcp_pid(self()) do
      DevicePool.idle(dev.address)
    end
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

  defp speed_notify(socket, result) do
    data = %{
      id: @cmd_speed_notify,
      result: result
    }

    resp = <<@protocol_type_data>> <> Poison.encode!(data)
    size = byte_size(resp)
    :ranch_tcp.send(socket, [<<size::32>>, resp])
  end

  defp speed_notify(socket, result, upload_speed, download_speed) do
    data = %{
      id: @cmd_speed_notify,
      result: result,
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
        {:ok, data} = :ranch_tcp.recv(socket, @speed_test_packet_len, @speed_timeout)
        Process.sleep(@speed_test_interval)
        speed_test_recv_loop(socket, size - byte_size(data))

      size < @speed_test_packet_len ->
        {:ok, _data} = :ranch_tcp.recv(socket, size, @speed_timeout)
        speed_test_recv_loop(socket, 0)
    end
  end

  defp check_remote_promise(promise, cid, from, to) do
    with false <- is_nil(promise),
         {:ok, promise} <- Poison.decode(promise, as: %Promise{}),
         true <- Promise.verify(promise, from, to),
         decoded_promise <- Promise.decode(promise),
         true <- cid == decoded_promise.cid do
      decoded_promise
    else
      _ -> nil
    end
  end

  defp check_local_promise(local_promise, cid, from, to) do
    if local_promise && local_promise.cid > 0 && cid == local_promise.cid &&
         Promise.verify(local_promise, from, to) do
      local_promise
    else
      nil
    end
  end
end
