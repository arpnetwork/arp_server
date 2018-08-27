defmodule ARP.Init do
  @moduledoc """
  Initialize server
  """

  alias ARP.{Config, Contract}

  require Logger

  def init do
    data_path = Config.get(:data_dir)

    unless File.exists?(data_path) do
      File.mkdir_p!(data_path)
    end

    # import keystore file
    keystore = read_keystore(Config.get(:keystore_file)) || Config.get_keystore()

    auth = ExPrompt.password("input your keystore password:") |> String.trim_trailing("\n")

    if ARP.Account.init_key(keystore, auth) == :ok do
      {:ok, %{addr: addr, private_key: private_key}} = ARP.Account.get_info()

      base_deposit = Config.get(:base_deposit)

      config_ip = Config.get(:ip) |> ARP.Utils.ip_to_integer()
      port = Config.get(:port)
      deposit = Config.get(:deposit)
      spender = Application.get_env(:arp_server, :registry_contract_address)

      with %{ip: ip} when ip == 0 <- Contract.get_registered_info(addr),
           Logger.info("registering..."),
           :ok <- check_eth_balance(addr),
           :ok <- check_arp_balance(addr),
           {:ok, %{"status" => "0x1"}} <- Contract.approve(private_key, deposit),
           {:ok, %{"status" => "0x1"}} <- Contract.bank_deposit(private_key, deposit),
           {:ok, %{"status" => "0x1"}} <-
             Contract.bank_approve(private_key, spender, base_deposit, 0),
           {:ok, %{"status" => "0x1"}} <- Contract.register(private_key, config_ip, port) do
        Logger.info("arp server is running!")
        :ok
      else
        %{ip: ip} when ip != 0 ->
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
    else
      Logger.error("keystore file invalid or password error!")
      :error
    end
  end

  def unregister do
    {:ok, %{private_key: private_key, addr: server_addr}} = ARP.Account.get_info()
    now = DateTime.utc_now() |> DateTime.to_unix()

    server_info = Contract.get_registered_info(server_addr)

    cond do
      server_info.ip != 0 && server_info.expired == 0 ->
        {:ok, %{"status" => "0x1"}} = Contract.unregister(private_key)

        # dapp
        info = ARP.DappPromise.get_all()
        Enum.each(info, fn {k, v} -> check_dapp_bind(k, v, private_key, server_addr) end)

        # device
        device_list = Contract.get_bound_device(server_addr)

        Enum.each(device_list, fn device_addr ->
          check_device_bind(device_addr, private_key, server_addr)
        end)

      server_info.ip != 0 && server_info.expired != 0 && now > server_info.expired ->
        {:ok, %{"status" => "0x1"}} = Contract.unregister(private_key)

      true ->
        :ok
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
    eth_balance = Contract.get_eth_balance(address)

    if eth_balance >= round(1.0e18) do
      :ok
    else
      {:error, "eth balance is not enough!"}
    end
  end

  defp check_arp_balance(address) do
    arp_balance = Contract.get_arp_balance(address)

    if arp_balance >= 5000 * round(1.0e18) do
      :ok
    else
      {:error, "arp balance is not enough!"}
    end
  end

  defp check_dapp_bind(dapp_addr, info, private_key, server_addr) do
    %{id: cid, paid: paid} = Contract.bank_allowance(dapp_addr, server_addr)

    if info["cid"] == cid && info["amount"] > paid do
      {:ok, %{"status" => "0x1"}} =
        Contract.bank_cash(private_key, dapp_addr, server_addr, info["amount"], info["sign"])
    end

    {:ok, %{"status" => "0x1"}} = Contract.unbind_app_by_server(private_key, dapp_addr)
    ARP.DappPromise.delete(dapp_addr)
  end

  defp check_device_bind(device_addr, private_key, server_addr) do
    %{server: server, expired: expired} = Contract.get_device_bind_info(device_addr)

    if server == server_addr && expired == 0 do
      {:ok, %{"status" => "0x1"}} = Contract.unbind_device_by_server(private_key, device_addr)
    end
  end
end
