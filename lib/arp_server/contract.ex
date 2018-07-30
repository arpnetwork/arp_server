defmodule ARP.Contract do
  @moduledoc """
  Define the api with the contract.
  """

  @chain_id Application.get_env(:arp_server, :chain_id)
  @contract_address Application.get_env(:arp_server, :contract_address)

  @default_gas_price 41_000_000_000
  @default_gas_limit 210_000

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
      to: @contract_address
    }

    {:ok, res} = Ethereumex.HttpClient.eth_call(params)
    hex_string_to_integer(res)
  end

  @doc """
  Transfer arp to some one.
  """
  def transfer_arp(
        private_key,
        from,
        to,
        value,
        gas_price \\ @default_gas_price,
        gas_limit \\ @default_gas_limit
      ) do
    to = to |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    encoded_abi = ABI.encode("transfer(address,uint)", [to, value])

    send_transaction(@contract_address, encoded_abi, private_key, from, gas_price, gas_limit)
  end

  @doc """
  Send transaction to a contract.
  """
  @spec send_transaction(String.t(), String.t(), String.t(), String.t(), integer, integer) ::
          {:ok, binary} | :error
  def send_transaction(contract_address, encoded_abi, private_key, from, gas_price, gas_limit) do
    private_key = Base.decode16!(private_key, case: :mixed)
    contract_address = contract_address |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    bt = %Blockchain.Transaction{
      nonce: get_transaction_count(from),
      gas_price: gas_price,
      gas_limit: gas_limit,
      to: contract_address,
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
