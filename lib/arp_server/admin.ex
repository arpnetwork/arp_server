defmodule ARP.Admin do
  @moduledoc """
  Admin service
  """

  alias ARP.{
    Account,
    Config,
    Contract,
    Crypto,
    Dapp,
    DappPool,
    DappPromise,
    DeviceBind,
    DevicePool,
    DevicePromise,
    Promise,
    Service,
    Utils
  }

  require Logger

  @status_stopped 0
  @status_starting 1
  @status_registering 2
  @status_running 3

  def init do
    :ets.new(__MODULE__, [:named_table, :public, read_concurrency: true])

    secret = Base.encode16(:crypto.strong_rand_bytes(64))
    :ets.insert(__MODULE__, [{:secret, secret}, {:status, @status_stopped}])
  end

  def get_secret do
    :ets.lookup_element(__MODULE__, :secret, 2)
  end

  def get_address do
    address = Account.address()
    keystore = Config.get(:keystore)

    cond do
      !is_nil(address) ->
        {:ok, address}

      !is_nil(keystore) && Map.has_key?(keystore, "address") ->
        {:ok, "0x" <> keystore["address"]}

      !is_nil(keystore) ->
        {:ok, "*"}

      true ->
        {:error, :missing_keystore}
    end
  end

  def import_keystore(keystore, password) do
    keystore = keystore |> String.downcase() |> Poison.decode!()

    with false <- Account.has_key(),
         :ok <- Account.set_key(keystore, password) do
      Config.set(:keystore, keystore)
    else
      true ->
        {:error, :already_imported_keystore}

      err ->
        err
    end
  end

  def verify_password(password) do
    keystore = Config.get(:keystore)

    cond do
      is_nil(keystore) ->
        {:error, :missing_keystore}

      Account.has_key() ->
        private_key = Account.private_key()

        case Crypto.decrypt_keystore(keystore, password) do
          {:ok, ^private_key} -> :ok
          _ -> {:error, :password_error}
        end

      true ->
        Account.set_key(keystore, password)
    end
  end

  def set_config(configs) do
    configs =
      configs
      |> Enum.map(fn {key, value} ->
        {key |> Macro.underscore() |> String.to_existing_atom(), value}
      end)
      |> Config.decode()

    Config.set(configs)
  end

  def get_external_config do
    config =
      Config.external()
      |> Config.encode()
      |> Enum.into(%{})

    {:ok, config}
  end

  def status do
    %{
      status: get_status(),
      load: DevicePool.size()
    }
  end

  def start do
    cond do
      get_status() != @status_stopped ->
        {:error, :service_already_started}

      nil == Account.private_key() ->
        {:error, :missing_keystore}

      false == Config.check() ->
        {:error, :missing_config}

      true ->
        set_status(@status_starting)

        Task.start(fn ->
          base_deposit = Config.get(:base_deposit)
          config_ip = Config.get(:ip) |> Utils.ip_to_integer()
          port = Config.get(:port)
          deposit = Config.get(:deposit)
          spender = Application.get_env(:arp_server, :registry_contract_address)

          private_key = Account.private_key()
          addr = Account.address()

          with {:ok, %{ip: ip}} when ip == 0 <- Contract.get_registered_info(addr),
               Logger.info("registering..."),
               set_status(@status_registering),
               :ok <- check_eth_balance(addr),
               {:ok, add} <- check_arp_balance(addr, deposit),
               {:ok, %{"status" => "0x1"}} <- Contract.approve(private_key, deposit),
               {:ok, %{"status" => "0x1"}} <- Contract.bank_deposit(private_key, add),
               {:ok, %{"status" => "0x1"}} <-
                 Contract.bank_approve(private_key, spender, base_deposit, 0),
               {:ok, %{"status" => "0x1"}} <- Contract.register(private_key, config_ip, port) do
            Service.start_service()
            DappPool.load_bound_dapp()
            set_status(@status_running)

            Logger.info("arp server is running!")
            :ok
          else
            {:ok, %{ip: ip}} when ip != 0 ->
              Service.start_service()
              DappPool.load_bound_dapp()
              set_status(@status_running)

              Logger.info("arp server is running!")
              :ok

            {:ok, %{"status" => "0x0"}} ->
              Logger.error("register failed!")
              {:error, :register_failed}

            {:error, e} ->
              Logger.error(inspect(e))
              :error

            e ->
              Logger.error(inspect(e))
              :error
          end
        end)

        :ok
    end
  end

  def stop do
    Service.stop_service()
    set_status(@status_stopped)
    Logger.info("arp server stopped!")
    :ok
  end

  def unregister do
    stop()

    private_key = Account.private_key()
    server_addr = Account.address()
    now = DateTime.utc_now() |> DateTime.to_unix()

    with {:ok, %{ip: ip, expired: expired}} <- Contract.get_registered_info(server_addr) do
      cond do
        ip != 0 && expired == 0 ->
          {:ok, %{"status" => "0x1"}} = Contract.unregister(private_key)

          # dapp
          info = DappPromise.get_all()
          Enum.each(info, fn {k, v} -> check_dapp_bind(k, v, private_key, server_addr) end)

          # device
          with {:ok, device_list} <- Contract.get_bound_device(server_addr) do
            Enum.each(device_list, fn device_addr ->
              check_device_bind(device_addr, private_key, server_addr)
            end)
          end

        ip != 0 && expired != 0 && now > expired ->
          {:ok, %{"status" => "0x1"}} = Contract.unregister(private_key)

        true ->
          :ok
      end
    else
      _ ->
        {:error, :network_error}
    end
  end

  def account do
    address = Account.address()

    with {:ok, eth} <- Contract.get_eth_balance(address),
         {:ok, arp} <- Contract.get_arp_balance(address),
         {:ok, bank} <- Contract.bank_balance(address),
         {:ok, base_deposit} <- Contract.bank_allowance(address),
         {:ok, devices} <- Contract.get_bound_device(address) do
      device_deposit =
        Enum.reduce(devices, 0, fn device, acc ->
          acc +
            case Contract.bank_allowance(address, device) do
              {:ok, deposit} -> deposit[:amount] - deposit[:paid]
              _ -> 0
            end
        end)

      %{
        eth: eth |> Utils.encode_integer(),
        arp: arp |> Utils.encode_integer(),
        bank: bank |> Utils.encode_integer(),
        device_deposit: device_deposit |> Utils.encode_integer(),
        base_deposit: base_deposit[:amount] |> Utils.encode_integer()
      }
    else
      _ ->
        {:error, :network_error}
    end
  end

  def device_list(nil) do
    device_list("all")
  end

  def device_list(type) do
    type = String.to_existing_atom(type)

    case type do
      :all ->
        # all bound devices.
        with address when not is_nil(address) <- Account.address(),
             {:ok, devices} <- Contract.get_bound_device(address) do
          bind_list = DeviceBind.get_all()

          device_list =
            Enum.reduce(bind_list, [], fn {device_addr, sub_list}, acc ->
              if Enum.member?(devices, device_addr) do
                sub_addr_list = Enum.map(sub_list, fn {sub_addr, _} -> sub_addr end)
                sub_addr_list ++ acc
              else
                acc
              end
            end)

          list = Enum.map(device_list, fn addr -> %{address: addr} end)
          {:ok, list}
        else
          nil ->
            {:error, :missing_password}

          err ->
            err
        end

      :online ->
        # online devices
        devices = DevicePool.get_all()
        list = Enum.map(devices, fn {addr, _, _} -> %{address: addr} end)
        {:ok, list}

      _ ->
        {:error, :invalid_params}
    end
  end

  def device_detail(address) do
    case ARP.DevicePool.get(address) do
      {_, dev} ->
        promise = ARP.DevicePromise.get(dev.device_address)

        p =
          if promise do
            Map.from_struct(promise)
          end

        data = dev |> Map.from_struct() |> Map.delete(:tcp_pid) |> Map.put(:promise, p)
        {:ok, data}

      _ ->
        {:error, :device_offline}
    end
  end

  def device_promise_list do
    list = DevicePromise.get_all()

    {:ok,
     Enum.reduce(list, [], fn {_, promise}, acc ->
       cid = promise.cid

       paid =
         case Contract.bank_allowance(promise.from, promise.to) do
           {:ok, %{id: ^cid, paid: paid}} -> paid
           {:ok, _} -> nil
           _ -> 0
         end

       if is_nil(paid) do
         DevicePromise.delete(promise.to)
         acc
       else
         item =
           promise
           |> struct(paid: paid)
           |> Promise.encode()
           |> Map.from_struct()

         [item | acc]
       end
     end)}
  end

  def dapp_list do
    list = DappPool.get_all()
    {:ok, Enum.map(list, fn {addr, _} -> %{address: addr} end)}
  end

  def dapp_detail(address) do
    case DappPool.get(address) do
      nil ->
        {:error, :unknow_address}

      pid ->
        device_list = DevicePool.get_by_dapp(address)
        dapp = Dapp.get(pid)
        {:ok, %{ip: dapp.ip, port: dapp.port, device_count: length(device_list)}}
    end
  end

  def dapp_promise_list do
    list = DappPromise.get_all()
    {:ok, Enum.map(list, fn {_, promise} -> promise |> Promise.encode() |> Map.from_struct() end)}
  end

  def cash_dapp_promise(address) do
    with pid when not is_nil(pid) <- DappPool.get(address),
         :ok <- Dapp.cash(pid) do
      :ok
    else
      _ ->
        {:error, :unknow_address}
    end
  end

  defp set_status(status) do
    :ets.insert(__MODULE__, {:status, status})
  end

  defp get_status do
    :ets.lookup_element(__MODULE__, :status, 2)
  end

  defp check_eth_balance(address) do
    with {:ok, eth_balance} when eth_balance >= round(1.0e18) <- Contract.get_eth_balance(address) do
      :ok
    else
      _ ->
        {:error, :eth_balance_is_not_enough}
    end
  end

  defp check_arp_balance(address, amount) do
    with {:ok, arp_balance} <- Contract.get_arp_balance(address),
         {:ok, bank_balance} <- Contract.bank_balance(address) do
      add = amount - bank_balance

      if arp_balance >= add do
        {:ok, add}
      else
        {:error, :arp_balance_is_not_enough}
      end
    else
      _ ->
        {:error, :arp_balance_is_not_enough}
    end
  end

  defp check_dapp_bind(dapp_addr, info, private_key, server_addr) do
    with {:ok, %{id: cid, paid: paid}} <- Contract.bank_allowance(dapp_addr, server_addr) do
      if info.cid == cid && info.amount > paid do
        {:ok, %{"status" => "0x1"}} =
          Contract.bank_cash(private_key, dapp_addr, server_addr, info.amount, info.sign)
      end

      {:ok, %{"status" => "0x1"}} = Contract.unbind_app_by_server(private_key, dapp_addr)
      DappPromise.delete(dapp_addr)
    end
  end

  defp check_device_bind(device_addr, private_key, server_addr) do
    with {:ok, %{server: server, expired: expired}} <- Contract.get_device_bind_info(device_addr) do
      if server == server_addr && expired == 0 do
        {:ok, %{"status" => "0x1"}} = Contract.unbind_device_by_server(private_key, device_addr)
      end
    end
  end
end
