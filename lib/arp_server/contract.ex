defmodule ARP.Contract do
  @moduledoc """
  Define the api with the contract.
  """

  @chain_id Application.get_env(:arp_server, :chain_id)
  @token_contract Application.get_env(:arp_server, :token_contract_address)
  @registry_contract Application.get_env(:arp_server, :registry_contract_address)

  @default_gas_price 41_000_000_000
  @default_gas_limit 200_000

  alias ARP.Crypto

  @doc """
  Get the eth balance by calling the rpc api of the block chain node.
  """
  @spec get_eth_balance(String.t()) :: integer | :error
  def get_eth_balance(address) do
    {:ok, res} = Ethereumex.HttpClient.eth_get_balance(address)
    hex_string_to_integer(res)
  end

  @doc """
  Get the arp balance by calling the constract api.
  """
  @spec get_arp_balance(String.t()) :: integer | :error
  def get_arp_balance(address) do
    address = address |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    abi_encoded_data = ABI.encode("balanceOf(address)", [address]) |> Base.encode16(case: :lower)

    params = %{
      data: "0x" <> abi_encoded_data,
      to: @token_contract
    }

    {:ok, res} = Ethereumex.HttpClient.eth_call(params)
    hex_string_to_integer(res)
  end

  @doc """
  Approve to registry contract.
  """
  @spec approve(String.t(), integer, integer, integer) :: {:ok, binary} | :error
  def approve(
        private_key,
        value,
        gas_price \\ @default_gas_price,
        gas_limit \\ @default_gas_limit
      ) do
    address = @registry_contract |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    encoded_abi = ABI.encode("approve(address,uint256)", [address, value])

    send_transaction(@token_contract, encoded_abi, private_key, gas_price, gas_limit)
  end

  @doc """
  Register miner.
  """
  @spec register(String.t(), integer, integer, integer, integer, integer, integer) ::
          {:ok, binary} | :error
  def register(
        private_key,
        ip,
        port,
        capacity,
        amount,
        gas_price \\ @default_gas_price,
        gas_limit \\ @default_gas_limit
      ) do
    encoded_abi =
      ABI.encode("register(uint32,uint16,uint256,uint256)", [ip, port, capacity, amount])

    send_transaction(@registry_contract, encoded_abi, private_key, gas_price, gas_limit)
  end

  @doc """
  Get registed info.
  """
  @spec get_registered_info(String.t()) :: map()
  def get_registered_info(address) do
    address = address |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    encoded_abi = ABI.encode("servers(address)", [address]) |> Base.encode16(case: :lower)

    params = %{
      data: "0x" <> encoded_abi,
      to: @registry_contract
    }

    {:ok, res} = Ethereumex.HttpClient.eth_call(params)
    res = res |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    <<ip::size(256), port::size(256), capacity::size(256), amount::size(256), expired::size(256),
      deviceCount::size(256)>> = res

    %{
      ip: ip,
      port: port,
      capacity: capacity,
      amount: amount,
      expired: expired,
      deviceCount: deviceCount
    }
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
  @spec send_transaction(String.t(), String.t(), String.t(), integer, integer) ::
          {:ok, binary} | :error
  def send_transaction(contract, encoded_abi, private_key, gas_price, gas_limit) do
    from = Crypto.eth_privkey_to_pubkey(private_key) |> Crypto.get_eth_addr()
    private_key = Base.decode16!(private_key, case: :mixed)
    contract = contract |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    bt = %Blockchain.Transaction{
      nonce: get_transaction_count(from),
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

    Ethereumex.HttpClient.eth_send_raw_transaction("0x" <> transaction_data)
  end

  @doc """
  Get pending transaction count.
  """
  @spec get_transaction_count(String.t()) :: integer
  def get_transaction_count(address) do
    {:ok, res} = Ethereumex.HttpClient.eth_get_transaction_count(address, "pending")
    hex_string_to_integer(res)
  end

  @spec hex_string_to_integer(String.t()) :: integer
  defp hex_string_to_integer(string) do
    string = String.trim_leading(string, "0x")
    len = String.length(string)

    string
    |> String.pad_leading(len + Integer.mod(len, 2), "0")
    |> Base.decode16!(case: :lower)
    |> :binary.decode_unsigned(:big)
  end
end
