defmodule ARP.Init do
  @moduledoc """
  Initialize server
  """

  alias ARP.{Config, Contract}

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
      eth_balance = Contract.get_eth_balance(addr)
      arp_balance = Contract.get_arp_balance(addr)

      ip = Config.get(:ip) |> ARP.Utils.ip_to_integer()
      port = Config.get(:port)
      approve = Config.get(:approve)
      bank = 200_000 * round(1.0e18)
      amount = 100_000 * round(1.0e18)

      # balance check
      if eth_balance < 1 * round(1.0e18) do
        IO.puts("eth balance is not enough!")
        :error
      else
        map = Contract.get_registered_info(addr)

        if map.ip == 0 do
          unless arp_balance < bank do
            allowance = Contract.allowance(addr)

            IO.puts("server is registering, please wait!")

            if allowance == 0 || allowance < amount do
              Contract.approve(
                private_key,
                approve
              )
            end

            spender = Application.get_env(:arp_server, :registry_contract_address)

            with {:ok, %{"status" => "0x1"}} <- Contract.bank_deposit(private_key, bank),
                 {:ok, %{"status" => "0x1"}} <-
                   Contract.bank_approve(private_key, spender, amount, 0),
                 {:ok, %{"status" => "0x1"}} <- Contract.register(private_key, ip, port) do
              IO.puts(:stdio, "arp server is running!")
              :ok
            else
              _ ->
                IO.puts("register server error!")
                :error
            end
          else
            IO.puts("arp balance is not enough!")
            :error
          end
        else
          IO.puts(:stdio, "arp server is running!")
          :ok
        end
      end
    else
      IO.puts("keystore file invalid or password error!")
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
