defmodule ARP.Init do
  @moduledoc """
  Initialize server
  """

  def init do
    # import keystore file
    keystore_dir = Path.expand("~/.arp_server")
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

      ip = Keyword.get(all_env, :ip)
      port = Keyword.get(all_env, :port)
      approve = Keyword.get(all_env, :approve)
      capacity = Keyword.get(all_env, :capacity)
      amount = capacity * 100 + 100_000

      # balance check
      if eth_balance < 1 * round(1.0e18) || arp_balance < 100_000 * round(1.0e18) do
        IO.puts("balance is not enough!")
        :error
      else
        map = ARP.Contract.get_registered_info(addr)

        if map.ip == 0 do
          allowance = ARP.Contract.allowance(addr)

          if allowance == 0 || allowance < amount do
            ARP.Contract.approve(
              private_key,
              approve * round(1.0e18)
            )
          end

          ARP.Contract.register(
            private_key,
            ip_to_integer(ip),
            port,
            capacity,
            amount * round(1.0e18)
          )
        end

        IO.puts(:stdio, "arp server is running!")
        :ok
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

  defp ip_to_integer(ip) do
    [head | tail] = String.split(ip, ".")
    first = String.to_integer(head) * 256 * 256 * 256
    [head | tail] = tail
    second = String.to_integer(head) * 256 * 256
    [head | tail] = tail
    third = String.to_integer(head) * 256
    [head | _] = tail
    fourth = String.to_integer(head)
    first + second + third + fourth
  end
end
