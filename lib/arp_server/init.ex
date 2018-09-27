defmodule ARP.Init do
  @moduledoc """
  Initialize server
  """

  alias ARP.{Account, Config, Contract}

  require Logger

  def init do
    check_config()

    data_path = Config.get(:data_dir)

    unless File.exists?(data_path) do
      File.mkdir_p!(data_path)
    end

    base_deposit = Config.get(:base_deposit)
    config_ip = Config.get(:ip) |> ARP.Utils.ip_to_integer()
    port = Config.get(:port)
    deposit = Config.get(:deposit)
    spender = Application.get_env(:arp_server, :registry_contract_address)

    # import keystore file
    keystore = read_keystore(Config.get(:keystore_file)) || Config.get_keystore()

    auth = ExPrompt.password("input your keystore password:") |> String.trim_trailing("\n")

    with {:ok, %{private_key: private_key, address: addr}} <- Account.set_key(keystore, auth),
         {:ok, %{ip: ip}} when ip == 0 <- Contract.get_registered_info(addr),
         Logger.info("registering..."),
         :ok <- check_eth_balance(addr),
         {:ok, add} <- check_arp_balance(addr, deposit),
         {:ok, %{"status" => "0x1"}} <- Contract.approve(private_key, deposit),
         {:ok, %{"status" => "0x1"}} <- Contract.bank_deposit(private_key, add),
         {:ok, %{"status" => "0x1"}} <-
           Contract.bank_approve(private_key, spender, base_deposit, 0),
         {:ok, %{"status" => "0x1"}} <- Contract.register(private_key, config_ip, port) do
      Logger.info("arp server is running!")
      :ok
    else
      {:ok, %{ip: ip}} when ip != 0 ->
        Logger.info("arp server is running!")
        :ok

      {:ok, %{"status" => "0x0"}} ->
        Logger.error("register failed!")
        :error

      {:error, e} ->
        Logger.error(e)
        :error

      e ->
        Logger.error(inspect(e))
        :error
    end
  end

  def unregister do
    private_key = Account.private_key()
    server_addr = Account.address()
    now = DateTime.utc_now() |> DateTime.to_unix()

    with {:ok, %{ip: ip, expired: expired}} <- Contract.get_registered_info(server_addr) do
      cond do
        ip != 0 && expired == 0 ->
          {:ok, %{"status" => "0x1"}} = Contract.unregister(private_key)

          # dapp
          info = ARP.DappPromise.get_all()
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
        :error
    end
  end

  defp read_keystore(keystore_filepath) do
    with true <- is_binary(keystore_filepath),
         {:ok, file} <- File.read(keystore_filepath),
         {:ok, file_map} <- file |> String.downcase() |> Poison.decode(keys: :atoms) do
      file_map
    else
      _ ->
        nil
    end
  end

  defp check_eth_balance(address) do
    with {:ok, eth_balance} when eth_balance >= round(1.0e18) <- Contract.get_eth_balance(address) do
      :ok
    else
      _ ->
        {:error, "eth balance is not enough!"}
    end
  end

  defp check_arp_balance(address, amount) do
    with {:ok, arp_balance} <- Contract.get_arp_balance(address),
         {:ok, bank_balance} <- Contract.bank_balance(address) do
      add = amount - bank_balance

      if arp_balance >= add do
        {:ok, add}
      else
        {:error, "arp balance is not enough!"}
      end
    else
      _ ->
        {:error, "arp balance is not enough!"}
    end
  end

  defp check_dapp_bind(dapp_addr, info, private_key, server_addr) do
    with {:ok, %{id: cid, paid: paid}} <- Contract.bank_allowance(dapp_addr, server_addr) do
      if info.cid == cid && info.amount > paid do
        {:ok, %{"status" => "0x1"}} =
          Contract.bank_cash(private_key, dapp_addr, server_addr, info.amount, info.sign)
      end

      {:ok, %{"status" => "0x1"}} = Contract.unbind_app_by_server(private_key, dapp_addr)
      ARP.DappPromise.delete(dapp_addr)
    end
  end

  defp check_device_bind(device_addr, private_key, server_addr) do
    with {:ok, %{server: server, expired: expired}} <- Contract.get_device_bind_info(device_addr) do
      if server == server_addr && expired == 0 do
        {:ok, %{"status" => "0x1"}} = Contract.unbind_device_by_server(private_key, device_addr)
      end
    end
  end

  defp check_config do
    all_config = Config.all()
    all_env = Application.get_all_env(:arp_server)

    Enum.each(all_env, fn {k, _v} -> check_key(all_config, k) end)
  end

  defp check_key(all_config, k) do
    unless Keyword.has_key?(all_config, k) do
      Logger.error("#{k} in config can not null!")
      exit(:shutdown)
    end
  end
end
