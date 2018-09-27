defmodule ARP.Account do
  @moduledoc """
  Manage server account
  """

  alias ARP.{Config, Crypto, Dapp, DappPool, Promise, Contract, DevicePromise}

  require Logger

  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def pay(dapp_addr, promise, increment, device_addr) do
    self_addr = address()
    private_key = private_key()

    with {:ok, promise} <- Poison.decode(promise, as: %ARP.Promise{}),
         true <- Promise.verify(promise, dapp_addr, self_addr),
         promise = Promise.decode(promise),
         true <- check_dapp_amount(promise.amount, dapp_addr, self_addr),
         {:ok, incremental_amount} <-
           Dapp.save_promise(DappPool.get(dapp_addr), promise, increment) do
      device_promise =
        calc_device_promise(incremental_amount, device_addr, self_addr, private_key)

      Task.start(fn ->
        DevicePromise.pay(device_addr, device_promise)
      end)

      :ok
    else
      {:error, e} ->
        {:error, e}

      _ ->
        {:error, :invalid_promise}
    end
  rescue
    e ->
      Logger.error(e)
      {:error, :invalid_promise}
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

  defp check_dapp_amount(promise_amount, dapp_addr, server_addr) do
    with {:ok, %{amount: amount}} when promise_amount <= amount <-
           Contract.bank_allowance(dapp_addr, server_addr) do
      true
    else
      _ ->
        false
    end
  end

  defp calc_device_promise(incremental_amount, device_addr, server_addr, private_key) do
    # calc device amount and promise
    {_pid, %{cid: device_cid}} = ARP.DevicePool.get(device_addr)
    device_promise = DevicePromise.get(device_addr)

    last_device_amount =
      if device_promise == nil || device_promise.cid != device_cid do
        0
      else
        device_promise.amount
      end

    rate = Config.get(:divide_rate)
    increment = round(incremental_amount * (1 - rate))
    device_amount = last_device_amount + increment

    Promise.create(private_key, device_cid, server_addr, device_addr, device_amount)
  end
end
