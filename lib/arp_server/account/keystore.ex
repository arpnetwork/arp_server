defmodule ARP.Account.Keystore do
  @moduledoc """
  Keystore
  """

  alias ARP.Crypto

  require Logger

  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def set(keystore, auth) do
    GenServer.call(__MODULE__, {:set, keystore, auth})
  end

  def exists? do
    :ets.member(__MODULE__, :address)
  end

  def private_key do
    case :ets.lookup(__MODULE__, :private_key) do
      [{:private_key, key}] -> key
      [] -> nil
    end
  end

  def public_key do
    case :ets.lookup(__MODULE__, :public_key) do
      [{:public_key, key}] -> key
      [] -> nil
    end
  end

  def address do
    case :ets.lookup(__MODULE__, :address) do
      [{:address, addr}] -> addr
      [] -> nil
    end
  end

  # Callbacks

  def init(_opts) do
    :ets.new(__MODULE__, [:named_table, read_concurrency: true])
    {:ok, %{}}
  end

  def handle_call({:set, keystore, auth}, _from, state) do
    with {:ok, private_key} <- Crypto.decrypt_keystore(keystore, auth) do
      public_key = Crypto.eth_privkey_to_pubkey(private_key)
      address = Crypto.get_eth_addr(public_key)
      Logger.info("use address #{address}")

      data = [
        {:private_key, private_key},
        {:public_key, public_key},
        {:address, address}
      ]

      :ets.insert(__MODULE__, data)

      {:reply, :ok, state}
    else
      _ ->
        {:reply, {:error, :invalid_keystore_or_password}, state}
    end
  end
end
