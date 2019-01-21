defmodule ARP.API.TCP.DeviceProtocol do
  @moduledoc """
  tcp device protocol
  """

  alias ARP.{Account, Config, Contract, Crypto, DeviceManager}

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
  @cmd_send_device_promise 11
  @cmd_app_install 12
  @cmd_app_uninstall 13
  @cmd_app_start 14
  @cmd_app_start_done_report 15

  @cmd_result_success 0
  @cmd_result_ver_err -1
  @cmd_result_verify_err -2
  # @cmd_result_port_err -3
  @cmd_result_max_load_err -4
  @cmd_result_speed_test_err -5
  @cmd_result_speed_test_low -6

  @cmd_net_type_external 1
  @cmd_net_type_internal 2

  @timeout 60_000

  @speed_test_packet_len 10_485_760

  @ver "1.4"
  @compatible_ver [@ver, "1.3"]

  @doc false
  def start_link(ref, socket, transport, _opts \\ []) do
    pid =
      :proc_lib.spawn_link(__MODULE__, :init, [
        %{
          ref: ref,
          socket: socket,
          transport: transport,
          speed_test: %{
            dl_data_hash: nil,
            dl_start_time: nil,
            dl_end_time: nil,
            ul_start_time: nil,
            ul_receive_data_len: nil,
            ul_end_time: nil
          }
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
  def start_speed_test(pid) do
    Process.send(pid, :start_speed_test, [])
  end

  def speed_test_notify(pid, result) do
    Process.send(pid, {:speed_test_notify, result}, [])
  end

  @doc """
  Send alloc end notify to device
  """
  def alloc_end(pid, dapp_address) do
    Process.send(pid, {:alloc_end, dapp_address}, [])
  end

  def repeat_connect_offline(pid, addr) do
    GenServer.call(pid, {:repeat_connect_offline, addr}, @timeout)
  end

  def send_device_promise(pid, cid, from, to, amount, sign) do
    GenServer.cast(pid, {:send_device_promise, cid, from, to, amount, sign})
  end

  def app_install(pid, mode, package, url, filesize, md5) do
    GenServer.cast(pid, {:app_install, mode, package, url, filesize, md5})
  end

  def app_uninstall(pid, package) do
    GenServer.cast(pid, {:app_uninstall, package})
  end

  def app_start(pid, package) do
    GenServer.call(pid, {:app_start, package})
  end

  def get_app_start(pid, package) do
    GenServer.call(pid, {:get_app_start, package})
  end

  def check_app_start(pid, package) do
    case get_app_start(pid, package) do
      true ->
        :ok

      false ->
        Process.sleep(200)
        check_app_start(pid, package)
    end
  end

  @doc false
  def init(%{ref: ref, socket: socket, transport: transport} = state) do
    :ok = :ranch.accept_ack(ref)
    :ok = transport.setopts(socket, active: true, packet: @protocol_packet)

    Logger.debug(fn -> "socket connect." <> inspect(socket) end)

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
    sub_addr = Map.get(state, :sub_addr)

    Logger.debug(fn ->
      "socket disconnect." <>
        inspect(socket) <>
        " reason:" <> inspect(reason) <> ", device addr: #{device_addr}, sub_addr: #{sub_addr}"
    end)

    # Delete device info
    DeviceManager.offline(sub_addr)
  end

  @doc """
  Reveive protocol data
  """
  def handle_info({:tcp, socket, data}, %{socket: socket} = state) do
    if byte_size(data) > 0 do
      <<type::8, data::binary>> = data

      state =
        case type do
          @protocol_type_data ->
            %{id: id} = req = Poison.decode!(data, keys: :atoms!)
            handle_command(id, Map.get(req, :data), socket, state)

          @protocol_type_speed_test ->
            handle_command(:speed_test, data, socket, state)
        end

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

  def handle_info(:start_speed_test, %{socket: socket} = state) do
    pad_data = :crypto.strong_rand_bytes(@speed_test_packet_len)
    hash = :crypto.hash(:md5, pad_data) |> Base.encode16(case: :lower)
    now = DateTime.utc_now() |> DateTime.to_unix(:millisecond)

    # send download speed test data
    with :ok <- send_speed_test_dl_tag(socket),
         :ok <- send_speed_test_dl_data(socket, pad_data),
         :ok <- send_speed_test_dl_tag(socket) do
      speed_test = %{
        dl_data_hash: hash,
        dl_start_time: now,
        dl_end_time: nil,
        ul_start_time: nil,
        ul_receive_data_len: nil,
        ul_end_time: nil
      }

      {:noreply, %{state | speed_test: speed_test}}
    else
      _ ->
        speed_err_notify(socket)
        {:noreply, state}
    end
  end

  def handle_info({:speed_test_notify, result}, %{socket: socket, device_addr: address} = state) do
    if result do
      speed_notify(socket, @cmd_result_success)
    else
      speed_notify(socket, @cmd_result_speed_test_low)
      Process.send_after(self(), {:tcp_closed, socket}, 1000)
      Logger.debug(fn -> "device offline, reason: speed test low, device addr: #{address}" end)
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

  def handle_call({:repeat_connect_offline, addr}, _from, %{socket: socket} = state) do
    %{
      id: @cmd_repeat_connect_offline_notify,
      data: %{
        address: addr
      }
    }
    |> send_resp(socket)

    Logger.debug(fn -> "device offline, reason: repeat connect, device addr: #{addr}" end)

    {:stop, :normal, :ok, state}
  end

  def handle_call({:app_start, package}, _from, %{socket: socket} = state) do
    %{
      id: @cmd_app_start,
      data: %{
        package: package
      }
    }
    |> send_resp(socket)

    state = Map.put(state, :app_start, :starting)

    {:reply, :ok, state}
  end

  def handle_call({:get_app_start, _package}, _from, state) do
    case state[:app_start] do
      :done ->
        {:reply, true, state}

      _ ->
        {:reply, false, state}
    end
  end

  def handle_cast({:send_device_promise, cid, from, to, amount, sign}, %{socket: socket} = state) do
    %{
      id: @cmd_send_device_promise,
      data: %{
        cid: cid,
        from: from,
        to: to,
        amount: amount,
        sign: sign
      }
    }
    |> send_resp(socket)

    {:noreply, state}
  end

  def handle_cast({:app_install, mode, package, url, filesize, md5}, %{socket: socket} = state) do
    %{
      id: @cmd_app_install,
      data: %{
        mode: mode,
        package: package,
        url: url,
        filesize: filesize,
        md5: md5
      }
    }
    |> send_resp(socket)

    {:noreply, state}
  end

  def handle_cast({:app_uninstall, package}, %{socket: socket} = state) do
    %{
      id: @cmd_app_uninstall,
      data: %{
        package: package
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

    # check device_addr valid
    private_key = Account.private_key()
    addr = Account.address()

    with {:ok, sub_addr} <- Crypto.eth_recover(salt, sign),
         device_addr when not is_nil(device_addr) <- DeviceManager.get_owner_address(sub_addr),
         {:ok, %{server: ^addr}} <- Contract.get_device_bind_info(device_addr),
         {:ok, %{id: cid, paid: paid}} <- Contract.bank_allowance(addr, device_addr) do
      state = Map.put(state, :device_addr, device_addr)

      # check promise
      remote_promise = check_remote_promise(promise, cid, addr, device_addr)
      local_promise = Account.get_device_promise(device_addr)
      local_promise = check_local_promise(local_promise, cid, addr, device_addr)

      cond do
        cid == 0 ->
          # promise is invalid
          Account.delete_device_promise(device_addr)

        remote_promise && (is_nil(local_promise) || local_promise.amount < remote_promise.amount) ->
          # recover device promise when local promise is invalid
          Account.set_device_promise(device_addr, remote_promise)

        is_nil(local_promise) && is_nil(remote_promise) ->
          Account.set_device_promise(
            device_addr,
            Account.create_promise(private_key, cid, addr, device_addr, paid)
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
    ver = data[:ver]
    device_addr = Map.get(state, :device_addr)
    ip = get_ip(socket)
    host = data[:proxy] || ip
    sub_addr = data[:address]
    state = Map.put(state, :sub_addr, sub_addr)

    net_type =
      case DeviceManager.check_port(host |> to_charlist(), data[:tcp_port]) do
        :ok -> @cmd_net_type_external
        _ -> @cmd_net_type_internal
      end

    data = data |> Map.put(:net_type, net_type)

    cond do
      DeviceManager.size() >= Config.get(:max_load) ->
        online_resp(socket, @cmd_result_max_load_err)
        Process.send_after(self(), {:tcp_closed, socket}, 5000)

        Logger.info(
          "online faild, reason: max load err, device addr: #{device_addr}, sub_addr: #{sub_addr}"
        )

      !device_addr ->
        online_resp(socket, @cmd_result_verify_err)
        Process.send_after(self(), {:tcp_closed, socket}, 5000)
        Logger.info("online faild, reason: device verify err, device addr: #{device_addr}")

      !DeviceManager.is_bind?(device_addr, sub_addr) ->
        online_resp(socket, @cmd_result_verify_err)
        Process.send_after(self(), {:tcp_closed, socket}, 5000)

        Logger.info(
          "online faild, reason: device sub_addr bind err, device addr: #{device_addr}, sub_addr: #{
            sub_addr
          }"
        )

      !Enum.member?(@compatible_ver, ver) ->
        online_resp(socket, @cmd_result_ver_err)
        Process.send_after(self(), {:tcp_closed, socket}, 5000)

        Logger.info(
          "online faild, reason: ver err, device addr: #{device_addr}, sub_addr: #{sub_addr}"
        )

      true ->
        addr = Account.address()

        features = data[:features]

        bpk =
          with true <- is_list(features),
               true <- Enum.member?(features, "bpk") do
            1
          else
            _ -> 0
          end

        landscape =
          with true <- is_list(features),
               true <- Enum.member?(features, "landscape") do
            1
          else
            _ -> 0
          end

        with {:ok, %{id: id}} when id != 0 <- Contract.bank_allowance(addr, device_addr),
             device = DeviceManager.create(data),
             device =
               struct(device, %{
                 owner_address: device_addr,
                 tcp_pid: self(),
                 ip: host,
                 original_ip: ip,
                 cid: id,
                 features: %{bpk: bpk, landscape: landscape}
               }),
             :ok <- online(device) do
          DeviceManager.test_speed(ip, sub_addr, self())

          online_resp(socket, @cmd_result_success, net_type)

          Logger.info("online success, device addr: #{device_addr}, sub_addr: #{sub_addr}")
        else
          _ ->
            online_resp(socket, @cmd_result_verify_err)
            Process.send_after(self(), {:tcp_closed, socket}, 5000)

            Logger.info(
              "online faild, reason: online err, device addr: #{device_addr}, sub_addr: #{
                sub_addr
              }"
            )
        end
    end

    state
  end

  # Check dl data hash
  defp handle_command(@cmd_dl_speed_report, data, socket, %{speed_test: speed_test} = state) do
    if !is_nil(data[:hash]) && data[:hash] == speed_test.dl_data_hash do
      now = DateTime.utc_now() |> DateTime.to_unix(:millisecond)
      speed_test = %{speed_test | dl_end_time: now}
      %{state | speed_test: speed_test}
    else
      speed_err_notify(socket)
      Process.send_after(self(), {:tcp_closed, socket}, 1000)
      device_addr = Map.get(state, :device_addr)
      sub_addr = Map.get(state, :sub_addr)

      Logger.debug(fn ->
        "device offline, reason: speed test hash err, device addr: #{device_addr}, sub_addr: #{
          sub_addr
        }"
      end)

      state
    end
  end

  # Receive speed test ul tag
  defp handle_command(:speed_test, <<>>, socket, %{speed_test: speed_test} = state) do
    cond do
      is_nil(speed_test.dl_end_time) ->
        speed_err_notify(socket)
        Process.send_after(self(), {:tcp_closed, socket}, 1000)
        device_addr = Map.get(state, :device_addr)
        sub_addr = Map.get(state, :sub_addr)

        Logger.debug(fn ->
          "device offline, reason: speed test tag err, device addr: #{device_addr}, sub_addr: #{
            sub_addr
          }"
        end)

        state

      is_nil(speed_test.ul_start_time) ->
        now = DateTime.utc_now() |> DateTime.to_unix(:millisecond)
        speed_test = %{speed_test | ul_start_time: now}
        %{state | speed_test: speed_test}

      is_nil(speed_test.ul_end_time) && speed_test.ul_receive_data_len == @speed_test_packet_len ->
        now = DateTime.utc_now() |> DateTime.to_unix(:millisecond)
        speed_test = %{speed_test | ul_end_time: now}

        dl_speed =
          round(
            @speed_test_packet_len / (speed_test.dl_end_time - speed_test.dl_start_time) * 1000
          )

        ul_speed = round(@speed_test_packet_len / (now - speed_test.ul_start_time) * 1000)

        ip = get_ip(socket)
        # set final speed
        Logger.debug(fn -> "net speed ul: #{ul_speed}, dl: #{dl_speed}, ip: #{ip}" end)
        DeviceManager.set_speed(ip, ul_speed, dl_speed)

        %{state | speed_test: speed_test}

      true ->
        speed_err_notify(socket)
        Process.send_after(self(), {:tcp_closed, socket}, 1000)
        device_addr = Map.get(state, :device_addr)
        sub_addr = Map.get(state, :sub_addr)

        Logger.debug(fn ->
          "device offline, reason: speed test tag err, device addr: #{device_addr}, sub_addr: #{
            sub_addr
          }"
        end)

        state
    end
  end

  # Receive speed test data
  defp handle_command(:speed_test, data, _socket, %{speed_test: speed_test} = state) do
    data_len = speed_test.ul_receive_data_len || 0
    speed_test = %{speed_test | ul_receive_data_len: data_len + byte_size(data)}
    %{state | speed_test: speed_test}
  end

  # Device use end report
  defp handle_command(@cmd_device_use_end_report, _data, _socket, state) do
    idle()
    state
  end

  defp handle_command(@cmd_app_start_done_report, _data, _socket, state) do
    Map.put(state, :app_start, :done)
  end

  defp online(:ok) do
    :ok
  end

  defp online(:error) do
    :error
  end

  defp online(device) do
    res =
      with :ok <- DeviceManager.online(device) do
        :ok
      else
        {:error, :duplicate_address} ->
          with {_, old_dev} <- DeviceManager.get(device.address) do
            repeat_connect_offline(old_dev.tcp_pid, device.address)
          end

          device

        _ ->
          :error
      end

    online(res)
  end

  defp idle do
    with {_, dev} <- DeviceManager.get_by_tcp_pid(self()) do
      DeviceManager.idle(dev.address)
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

  defp online_resp(socket, result, net_type) do
    %{
      id: @cmd_online_resp,
      result: result,
      data: %{
        net_type: net_type
      }
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

  defp speed_err_notify(socket) do
    data = %{
      id: @cmd_speed_notify,
      result: @cmd_result_speed_test_err
    }

    resp = <<@protocol_type_data>> <> Poison.encode!(data)
    size = byte_size(resp)
    :ranch_tcp.send(socket, [<<size::32>>, resp])
  end

  defp speed_notify(socket, result) do
    data = %{
      id: @cmd_speed_notify,
      result: result
    }

    send_resp(data, socket)
  end

  defp send_resp(resp, socket) do
    resp = <<@protocol_type_data>> <> Poison.encode!(resp)
    :ranch_tcp.send(socket, resp)
  end

  defp send_speed_test_dl_tag(socket) do
    msg = <<@protocol_type_speed_test>>
    :ranch_tcp.send(socket, msg)
  end

  defp send_speed_test_dl_data(socket, data) do
    msg = <<@protocol_type_speed_test>> <> data
    :ranch_tcp.send(socket, msg)
  end

  # Get device ip
  defp get_ip(socket) do
    {:ok, {ip, _}} = :ranch_tcp.peername(socket)
    ip |> Tuple.to_list() |> Enum.join(".")
  end

  defp check_remote_promise(promise, cid, from, to) do
    with false <- is_nil(promise),
         {:ok, promise} <- Poison.decode(promise, as: %Account.Promise{}),
         true <- Account.verify_promise(promise, cid, from, to) do
      Account.decode_promise(promise)
    else
      _ -> nil
    end
  end

  defp check_local_promise(local_promise, cid, from, to) do
    if local_promise && local_promise.cid > 0 && cid == local_promise.cid &&
         Account.verify_promise(local_promise, cid, from, to) do
      local_promise
    else
      nil
    end
  end
end
