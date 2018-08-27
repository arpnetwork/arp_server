defmodule ARP.Account do
  @moduledoc """
  Manage server account
  """

  alias ARP.{Config, Crypto}

  require Logger

  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def set_key(keystore, auth) do
    GenServer.call(__MODULE__, {:set_key, keystore, auth})
  end

  def private_key do
    [{:private_key, key}] = :ets.lookup(__MODULE__, :private_key)
    key
  end

  def public_key do
    [{:public_key, key}] = :ets.lookup(__MODULE__, :public_key)
    key
  end

  def address do
    [{:address, addr}] = :ets.lookup(__MODULE__, :address)
    addr
  end

  # Callbacks

  def init(_opts) do
    :ets.new(__MODULE__, [:named_table, read_concurrency: true])
    {:ok, []}
  end

  def handle_call({:set_key, keystore, auth}, _from, state) do
    with {:ok, private_key} <- Crypto.decrypt_keystore(keystore, auth) do
      public_key = Crypto.eth_privkey_to_pubkey(private_key)
      address = Crypto.get_eth_addr(public_key)
      Logger.info("use address #{address}")

      Config.set_keystore(keystore)

      data = [
        {:private_key, private_key},
        {:public_key, public_key},
        {:address, address}
      ]

      :ets.insert(__MODULE__, data)

      {:reply, {:ok, Enum.into(data, %{})}, state}
    else
      _ ->
        {:reply, {:error, "keystore file invalid or password error!"}, state}
    end
  end
end
