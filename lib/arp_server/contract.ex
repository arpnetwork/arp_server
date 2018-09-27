defmodule ARP.Contract do
  @moduledoc """
  Define the api with the contract.
  """

  @chain_id Application.get_env(:arp_server, :chain_id)
  @token_contract Application.get_env(:arp_server, :token_contract_address)
  @registry_contract Application.get_env(:arp_server, :registry_contract_address)
  @bank_contract Application.get_env(:arp_server, :bank_contract_address)
  @first_registry_block Application.get_env(:arp_server, :first_registry_block)

  @default_gas_price 41_000_000_000
  @default_gas_limit 200_000

  @receipt_block_time 15_000
  @receipt_attempts 40

  alias ARP.Crypto

  @doc """
  Get the eth balance by calling the rpc api of the block chain node.
  """
  @spec get_eth_balance(String.t()) :: {:ok, integer()} | {:error, any()}
  def get_eth_balance(address) do
    with {:ok, res} <- Ethereumex.HttpClient.eth_get_balance(address) do
      {:ok, hex_string_to_integer(res)}
    else
      err -> err
    end
  end

  @doc """
  Get the arp balance by calling the constract api.
  """
  @spec get_arp_balance(String.t()) :: {:ok, integer()} | {:error, any()}
  def get_arp_balance(address) do
    address = address |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    abi_encoded_data = ABI.encode("balanceOf(address)", [address]) |> Base.encode16(case: :lower)

    params = %{
      data: "0x" <> abi_encoded_data,
      to: @token_contract
    }

    with {:ok, res} <- Ethereumex.HttpClient.eth_call(params) do
      {:ok, hex_string_to_integer(res)}
    else
      err -> err
    end
  end

  @doc """
  Get allowance.
  """
  @spec allowance(String.t()) :: {:ok, integer()} | {:error, any()}
  def allowance(owner) do
    owner = owner |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    spender = @bank_contract |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    abi_encoded_data =
      ABI.encode("allowance(address,address)", [owner, spender]) |> Base.encode16(case: :lower)

    params = %{
      data: "0x" <> abi_encoded_data,
      to: @token_contract
    }

    with {:ok, res} <- Ethereumex.HttpClient.eth_call(params) do
      {:ok, hex_string_to_integer(res)}
    else
      err -> err
    end
  end

  @doc """
  Approve to registry contract.
  """
  def approve(
        private_key,
        value,
        gas_price \\ @default_gas_price,
        gas_limit \\ @default_gas_limit
      ) do
    address = @bank_contract |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    encoded_abi = ABI.encode("approve(address,uint256)", [address, value])

    send_transaction(@token_contract, encoded_abi, private_key, gas_price, gas_limit)
  end

  @doc """
  Register miner.
  """
  def register(
        private_key,
        ip,
        port,
        gas_price \\ @default_gas_price,
        gas_limit \\ @default_gas_limit
      ) do
    encoded_abi = ABI.encode("registerServer(uint32,uint16)", [ip, port])

    send_transaction(@registry_contract, encoded_abi, private_key, gas_price, gas_limit)
  end

  @doc """
  Unregister miner.
  """
  def unregister(private_key, gas_price \\ @default_gas_price, gas_limit \\ @default_gas_limit) do
    encoded_abi = ABI.encode("unregisterServer()", [])

    send_transaction(@registry_contract, encoded_abi, private_key, gas_price, gas_limit)
  end

  @doc """
  Get registed info.
  """
  @spec get_registered_info(String.t()) :: {:ok, map()} | {:error, any()}
  def get_registered_info(address) do
    address = address |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    encoded_abi = ABI.encode("servers(address)", [address]) |> Base.encode16(case: :lower)

    params = %{
      data: "0x" <> encoded_abi,
      to: @registry_contract
    }

    with {:ok, res} <- Ethereumex.HttpClient.eth_call(params) do
      res = res |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
      res = if bit_size(res) != 1024, do: <<0::size(1024)>>, else: res

      <<ip::size(256), port::size(256), size::size(256), expired::size(256)>> = res

      {:ok,
       %{
         ip: ip,
         port: port,
         size: size,
         expired: expired
       }}
    else
      err -> err
    end
  end

  @doc """
  get device bind info
  """
  @spec get_device_bind_info(String.t()) :: {:ok, map()} | {:error, any()}
  def get_device_bind_info(address) do
    address = address |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    address = (<<0>> |> :binary.copy(32 - byte_size(address))) <> address
    encoded_abi = ABI.encode("bindings(bytes32)", [address]) |> Base.encode16(case: :lower)

    params = %{
      data: "0x" <> encoded_abi,
      to: @registry_contract
    }

    with {:ok, res} <- Ethereumex.HttpClient.eth_call(params) do
      res = res |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
      res = if bit_size(res) != 512, do: <<0::size(512)>>, else: res

      <<server::binary-size(32), expired::size(256)>> = res

      server = server |> binary_part(12, byte_size(server) - 12) |> Base.encode16(case: :lower)

      {:ok,
       %{
         server: "0x" <> server,
         expired: expired
       }}
    else
      err -> err
    end
  end

  def get_dapp_bind_info(dapp_addr, server_addr) do
    dapp_addr = dapp_addr |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    server_addr = server_addr |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    data = Crypto.keccak256(dapp_addr <> server_addr)

    encoded_abi = ABI.encode("bindings(bytes32)", [data]) |> Base.encode16(case: :lower)

    params = %{
      data: "0x" <> encoded_abi,
      to: @registry_contract
    }

    with {:ok, res} <- Ethereumex.HttpClient.eth_call(params) do
      res = res |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
      res = if bit_size(res) != 512, do: <<0::size(512)>>, else: res

      <<server::binary-size(32), expired::size(256)>> = res

      server = server |> binary_part(12, byte_size(server) - 12) |> Base.encode16(case: :lower)

      {:ok,
       %{
         server: "0x" <> server,
         expired: expired
       }}
    else
      err -> err
    end
  end

  def get_device_holding() do
    encoded_abi = ABI.encode("DEVICE_HOLDING()", []) |> Base.encode16(case: :lower)

    params = %{
      data: "0x" <> encoded_abi,
      to: @registry_contract
    }

    with {:ok, res} <- Ethereumex.HttpClient.eth_call(params) do
      {:ok, hex_string_to_integer(res)}
    else
      err -> err
    end
  end

  def unbind_device_by_server(
        private_key,
        device_addr,
        gas_price \\ @default_gas_price,
        gas_limit \\ @default_gas_limit
      ) do
    device_addr = device_addr |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    encoded_abi = ABI.encode("unbindDeviceByServer(address)", [device_addr])

    send_transaction(@registry_contract, encoded_abi, private_key, gas_price, gas_limit)
  end

  def unbind_app_by_server(
        private_key,
        dapp_addr,
        gas_price \\ @default_gas_price,
        gas_limit \\ @default_gas_limit
      ) do
    dapp_addr = dapp_addr |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    encoded_abi = ABI.encode("unbindAppByServer(address)", [dapp_addr])

    send_transaction(@registry_contract, encoded_abi, private_key, gas_price, gas_limit)
  end

  def bank_deposit(
        private_key,
        value,
        gas_price \\ @default_gas_price,
        gas_limit \\ @default_gas_limit
      ) do
    encoded_abi = ABI.encode("deposit(uint256)", [value])

    send_transaction(@bank_contract, encoded_abi, private_key, gas_price, gas_limit)
  end

  def bank_withdraw(
        private_key,
        value,
        gas_price \\ @default_gas_price,
        gas_limit \\ @default_gas_limit
      ) do
    encoded_abi = ABI.encode("withdraw(uint256)", [value])

    send_transaction(@bank_contract, encoded_abi, private_key, gas_price, gas_limit)
  end

  def bank_balance(owner) do
    owner = owner |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    abi_encoded_data = ABI.encode("balanceOf(address)", [owner]) |> Base.encode16(case: :lower)

    params = %{
      data: "0x" <> abi_encoded_data,
      to: @bank_contract
    }

    with {:ok, res} <- Ethereumex.HttpClient.eth_call(params) do
      {:ok, hex_string_to_integer(res)}
    else
      err -> err
    end
  end

  def bank_approve(
        private_key,
        spender,
        amount,
        expired,
        proxy \\ 0,
        gas_price \\ @default_gas_price,
        gas_limit \\ @default_gas_limit
      ) do
    spender = spender |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    proxy =
      if proxy != 0 do
        proxy |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
      else
        proxy
      end

    encoded_abi =
      ABI.encode("approve(address, uint256, uint256, address)", [spender, amount, expired, proxy])

    send_transaction(@bank_contract, encoded_abi, private_key, gas_price, gas_limit)
  end

  def bank_allowance(owner, spender \\ @registry_contract) do
    owner = owner |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    spender = spender |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    abi_encoded_data =
      ABI.encode("allowance(address,address)", [owner, spender]) |> Base.encode16(case: :lower)

    params = %{
      data: "0x" <> abi_encoded_data,
      to: @bank_contract
    }

    with {:ok, res} <- Ethereumex.HttpClient.eth_call(params) do
      res = res |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
      res = if bit_size(res) != 1280, do: <<0::size(1280)>>, else: res

      <<id::size(256), amount::size(256), paid::size(256), expired::size(256),
        proxy::binary-size(32)>> = res

      proxy = proxy |> binary_part(12, byte_size(proxy) - 12) |> Base.encode16(case: :lower)

      {:ok,
       %{
         id: id,
         amount: amount,
         paid: paid,
         expired: expired,
         proxy: "0x" <> proxy
       }}
    else
      err -> err
    end
  end

  def bank_increase_approval(
        private_key,
        spender,
        value,
        expired,
        gas_price \\ @default_gas_price,
        gas_limit \\ @default_gas_limit
      ) do
    spender = spender |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    encoded_abi =
      ABI.encode("increaseApproval(address, uint256, uint256)", [spender, value, expired])

    send_transaction(@bank_contract, encoded_abi, private_key, gas_price, gas_limit)
  end

  def bank_cash(
        private_key,
        owner,
        spender,
        amount,
        sign,
        gas_price \\ @default_gas_price,
        gas_limit \\ @default_gas_limit
      ) do
    owner = owner |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    spender = spender |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    <<r::binary-size(32), s::binary-size(32), v::size(8)>> = sign |> Base.decode16!(case: :mixed)

    encoded_abi =
      ABI.encode("cash(address, address, uint256, uint8, bytes32, bytes32)", [
        owner,
        spender,
        amount,
        v,
        r,
        s
      ])

    send_transaction(@bank_contract, encoded_abi, private_key, gas_price, gas_limit)
  end

  @spec get_bound_device(binary()) :: {:ok, any()} | {:error, atom() | binary() | map()}
  def get_bound_device(address) do
    bind_topic =
      "0x" <> Base.encode16(Crypto.keccak256("DeviceBound(address,address)"), case: :lower)

    unbind_topic =
      "0x" <> Base.encode16(Crypto.keccak256("DeviceUnbound(address,address)"), case: :lower)

    encoded_address = String.replace_prefix(address, "0x", "0x000000000000000000000000")

    params = %{
      fromBlock: @first_registry_block,
      toBlock: "latest",
      address: @registry_contract,
      topics: [[bind_topic, unbind_topic], nil, encoded_address]
    }

    with {:ok, id} <- Ethereumex.HttpClient.eth_new_filter(params),
         {:ok, logs} <- Ethereumex.HttpClient.eth_get_filter_logs(id),
         {:ok, _} <- Ethereumex.HttpClient.eth_uninstall_filter(id) do
      out =
        Enum.reduce(logs, [], fn item, acc ->
          if item["removed"] == false do
            [topic, device, _] = item["topics"]
            device = String.replace_prefix(device, "0x000000000000000000000000", "0x")

            if topic == bind_topic do
              [device | acc]
            else
              List.delete(acc, device)
            end
          else
            acc
          end
        end)

      {:ok, out}
    else
      err -> err
    end
  end

  @spec get_bound_dapp(binary()) :: {:ok, any()} | {:error, atom() | binary() | map()}
  def get_bound_dapp(address) do
    bind_topic =
      "0x" <> Base.encode16(Crypto.keccak256("AppBound(address,address)"), case: :lower)

    unbind_topic =
      "0x" <> Base.encode16(Crypto.keccak256("AppUnbound(address,address)"), case: :lower)

    encoded_address = String.replace_prefix(address, "0x", "0x000000000000000000000000")

    params = %{
      fromBlock: @first_registry_block,
      toBlock: "latest",
      address: @registry_contract,
      topics: [[bind_topic, unbind_topic], nil, encoded_address]
    }

    with {:ok, id} <- Ethereumex.HttpClient.eth_new_filter(params),
         {:ok, logs} <- Ethereumex.HttpClient.eth_get_filter_logs(id),
         {:ok, _} <- Ethereumex.HttpClient.eth_uninstall_filter(id) do
      out =
        Enum.reduce(logs, [], fn item, acc ->
          if item["removed"] == false do
            [topic, dapp, _] = item["topics"]
            dapp = String.replace_prefix(dapp, "0x000000000000000000000000", "0x")

            if topic == bind_topic do
              [dapp | acc]
            else
              List.delete(acc, dapp)
            end
          else
            acc
          end
        end)

      {:ok, out}
    else
      err -> err
    end
  end

  @doc """
  Transfer arp to some one.
  """
  def transfer_arp(
        private_key,
        to,
        value,
        gas_price \\ @default_gas_price,
        gas_limit \\ @default_gas_limit
      ) do
    to = to |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    encoded_abi = ABI.encode("transfer(address,uint)", [to, value])

    send_transaction(@token_contract, encoded_abi, private_key, gas_price, gas_limit)
  end

  @doc """
  Send transaction to a contract.
  """
  @spec send_transaction(String.t(), String.t(), String.t(), integer(), integer()) ::
          {:ok, map()} | {:error, any()}
  def send_transaction(contract, encoded_abi, private_key, gas_price, gas_limit) do
    from = Crypto.eth_privkey_to_pubkey(private_key) |> Crypto.get_eth_addr()
    private_key = Base.decode16!(private_key, case: :mixed)
    contract = contract |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    with {:ok, nonce} <- get_transaction_count(from) do
      bt = %Blockchain.Transaction{
        nonce: nonce,
        gas_price: gas_price,
        gas_limit: gas_limit,
        to: contract,
        value: 0,
        v: 0,
        r: 0,
        s: 0,
        init: <<>>,
        data: encoded_abi
      }

      transaction_data =
        bt
        |> Blockchain.Transaction.Signature.sign_transaction(private_key, @chain_id)
        |> Blockchain.Transaction.serialize()
        |> ExRLP.encode()
        |> Base.encode16(case: :lower)

      res = Ethereumex.HttpClient.eth_send_raw_transaction("0x" <> transaction_data)

      case res do
        {:ok, tx_hash} ->
          get_transaction_receipt(tx_hash, @receipt_attempts)

        _ ->
          res
      end
    else
      err -> err
    end
  end

  @doc """
  Get pending transaction count.
  """
  @spec get_transaction_count(String.t()) ::
          {:ok, integer()} | {:error, map() | binary() | atom()}
  def get_transaction_count(address) do
    with {:ok, res} <- Ethereumex.HttpClient.eth_get_transaction_count(address, "pending") do
      {:ok, hex_string_to_integer(res)}
    else
      err -> err
    end
  end

  @doc """
  Get transaction receipt.
  """
  @spec get_transaction_receipt(String.t(), integer(), term()) :: {:ok, map()}
  def get_transaction_receipt(tx_hash, attempts, res \\ {:ok, nil})

  def get_transaction_receipt(_tx_hash, 0, _) do
    {:error, :timeout}
  end

  def get_transaction_receipt(_tx_hash, _attempts, {:error, reason}) do
    {:error, reason}
  end

  def get_transaction_receipt(_tx_hash, _attempts, {:ok, receipt}) when is_map(receipt) do
    {:ok, receipt}
  end

  def get_transaction_receipt(tx_hash, attempts, _) do
    Process.sleep(@receipt_block_time)
    res = Ethereumex.HttpClient.eth_get_transaction_receipt(tx_hash)
    get_transaction_receipt(tx_hash, attempts - 1, res)
  end

  @spec hex_string_to_integer(String.t()) :: integer()
  defp hex_string_to_integer(string) do
    string = String.trim_leading(string, "0x")
    len = String.length(string)

    string
    |> String.pad_leading(len + Integer.mod(len, 2), "0")
    |> Base.decode16!(case: :lower)
    |> :binary.decode_unsigned(:big)
  end
end
