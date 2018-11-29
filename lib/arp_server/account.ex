defmodule ARP.Account do
  @moduledoc """
  Manage server account
  """

  alias ARP.API.TCP.DeviceProtocol

  alias ARP.{
    Config,
    Contract,
    Crypto,
    Dapp,
    DappPool,
    DeviceBind,
    DevicePool,
    DevicePromise,
    Promise,
    Utils
  }

  require Logger

  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def pay(dapp_addr, promise, increment, sub_addr) do
    self_addr = address()
    private_key = private_key()

    with {:ok, promise} <- Poison.decode(promise, as: %ARP.Promise{}),
         true <- Promise.verify(promise, dapp_addr, self_addr),
         promise = Promise.decode(promise),
         dapp_pid when not is_nil(dapp_pid) <- DappPool.get(dapp_addr),
         :ok <- Dapp.save_promise(dapp_pid, promise, increment),
         {:ok, device_addr} <- DeviceBind.get_device_addr(sub_addr),
         device_promise =
           calc_device_promise(increment, device_addr, sub_addr, self_addr, private_key),
         true <- check_device_amount(device_addr, device_promise.amount) do
      DevicePromise.set(device_addr, device_promise)

      with {_, dev} <- DevicePool.get(sub_addr) do
        DeviceProtocol.send_device_promise(
          dev.tcp_pid,
          device_promise.cid |> Utils.encode_integer(),
          device_promise.from,
          device_promise.to,
          device_promise.amount |> Utils.encode_integer(),
          device_promise.sign
        )
      end

      :ok
    else
      {:error, e} ->
        {:error, e}

      _ ->
        {:error, :invalid_promise}
    end
  rescue
    e ->
      Logger.error(inspect(e))
      {:error, :invalid_promise}
  end

  def set_key(keystore, auth) do
    GenServer.call(__MODULE__, {:set_key, keystore, auth})
  end

  def has_key do
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

  def set_allowance(device_addr) do
    GenServer.call(__MODULE__, {:set_allowance, device_addr})
  end

  def del_allowance(device_addr) do
    GenServer.call(__MODULE__, {:del_allowance, device_addr})
  end

  def check_allowance(device_addr, amount) do
    GenServer.call(__MODULE__, {:check_allowance, device_addr, amount})
  end

  def get_allowance do
    GenServer.call(__MODULE__, :get_allowance)
  end

  # Callbacks

  def init(_opts) do
    :ets.new(__MODULE__, [:named_table, read_concurrency: true])
    {:ok, %{}}
  end

  def handle_call({:set_key, keystore, auth}, _from, state) do
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

  def handle_call(:get_allowance, _from, state) do
    {:reply, state, state}
  end

  def handle_call({:set_allowance, device_addr}, _from, state) do
    server_addr = address()

    if state[device_addr] do
      {:reply, :ok, state}
    else
      with {:ok, allowance} <- Contract.bank_allowance(server_addr, device_addr),
           true <- allowance.id > 0,
           true <- allowance.expired == 0 do
        new_state = Map.put(state, device_addr, %{allowance: allowance, increasing: false})
        {:reply, :ok, new_state}
      else
        _ ->
          {:reply, {:error, :allowance_err}, state}
      end
    end
  end

  def handle_call({:del_allowance, device_addr}, _from, state) do
    state =
      case DevicePool.get_device_size(device_addr) do
        0 ->
          Map.delete(state, device_addr)

        _ ->
          state
      end

    {:reply, :ok, state}
  end

  def handle_call({:check_allowance, device_addr, amount}, _from, state) do
    if state[device_addr] do
      info = state[device_addr]
      allowance = info.allowance
      increasing = info.increasing

      size = DevicePool.get_device_size(device_addr)
      approval_amount = Config.get(:device_deposit) * size
      limit_amount = approval_amount * 0.5

      cond do
        allowance.amount < amount ->
          {:reply, :error, state}

        !increasing && allowance.amount - amount < limit_amount ->
          increase_approval(device_addr, approval_amount, allowance.expired)

          Logger.info(
            "device allowance less than #{limit_amount / 1.0e18} ARP, increasing. address: #{
              device_addr
            }"
          )

          info = %{info | increasing: true}
          new_state = Map.put(state, device_addr, info)

          {:reply, :ok, new_state}

        true ->
          {:reply, :ok, state}
      end
    else
      {:reply, :error, state}
    end
  end

  def handle_info({_ref, {:increase_result, device_addr, allowance}}, state) do
    Logger.debug(fn -> "increase result update allowance: " <> inspect(allowance) end)
    info = state[device_addr]

    if info do
      info = %{info | allowance: allowance, increasing: false}
      new_state = Map.put(state, device_addr, info)
      {:noreply, new_state}
    else
      {:noreply, state}
    end
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  defp check_device_amount(device_addr, amount) do
    with :ok <- check_allowance(device_addr, amount) do
      true
    else
      e ->
        Logger.debug(fn -> inspect(e) end, label: "check device amount")
        false
    end
  end

  defp calc_device_promise(incremental_amount, device_addr, sub_addr, server_addr, private_key) do
    # calc device amount and promise
    {_pid, %{cid: device_cid}} = DevicePool.get(sub_addr)
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

  defp increase_approval(device_addr, amount, expired) do
    Task.async(fn ->
      server_addr = address()
      private_key = private_key()

      with {:ok, %{"status" => "0x1"}} <-
             Contract.bank_increase_approval(private_key, device_addr, amount, expired) do
        Logger.info("increase allowance success. device_addr: #{device_addr}")
      end

      {:ok, new_allowance} = Contract.bank_allowance(server_addr, device_addr)

      {:increase_result, device_addr, new_allowance}
    end)
  end
end
