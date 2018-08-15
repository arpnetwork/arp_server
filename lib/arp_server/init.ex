defmodule ARP.Init do
  @moduledoc """
  Initialize server
  """

  def init do
    # import keystore file
    keystore_dir = System.user_home() |> Path.join("/.arp_server")
    all_env = Application.get_all_env(:arp_server)

    path =
      case check_keystore(keystore_dir) do
        {:ok, file_path} ->
          file_path

        :error ->
          src = Keyword.get(all_env, :keystore_file)

          file_name = Path.basename(src)
          des_path = Path.join(keystore_dir, file_name)
          :ok = src |> Path.expand() |> File.cp(des_path)
          des_path
      end

    auth = ExPrompt.password("input your keystore password:") |> String.trim_trailing("\n")

    if ARP.Account.init_key(path, auth) == :ok do
      {:ok, %{addr: addr, private_key: private_key}} = ARP.Account.get_info()
      eth_balance = ARP.Contract.get_eth_balance(addr)
      arp_balance = ARP.Contract.get_arp_balance(addr)

      ip = Keyword.get(all_env, :ip) |> ARP.Utils.ip_to_integer()
      port = Keyword.get(all_env, :port)
      approve = Keyword.get(all_env, :approve)
      bank = 200_000 * round(1.0e18)
      amount = 100_000 * round(1.0e18)

      # balance check
      if eth_balance < 1 * round(1.0e18) do
        IO.puts("eth balance is not enough!")
        :error
      else
        map = ARP.Contract.get_registered_info(addr)

        if map.ip == 0 do
          unless arp_balance < bank do
            allowance = ARP.Contract.allowance(addr)

            IO.puts("server is registering, please wait!")

            if allowance == 0 || allowance < amount do
              ARP.Contract.approve(
                private_key,
                approve
              )
            end

            spender = Application.get_env(:arp_server, :registry_contract_address)

            with {:ok, _} <- ARP.Contract.bank_deposit(private_key, bank),
                 {:ok, _} <- ARP.Contract.bank_approve(private_key, spender, amount, 0),
                 {:ok, _} <- ARP.Contract.register(private_key, ip, port) do
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

  defp check_keystore(keystore_dir) do
    with true <- File.exists?(keystore_dir), {:ok, list} <- File.ls(keystore_dir) do
      first = List.first(list)

      if first != nil do
        file_path = Path.join(keystore_dir, first)
        {:ok, file_path}
      else
        :error
      end
    else
      _ ->
        :ok = File.mkdir(keystore_dir)
        :error
    end
  end
end
