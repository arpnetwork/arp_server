defmodule ARP.Account do
  @moduledoc """
  Manage server account
  """

  alias ARP.{Config, Crypto, Utils, Contract, DappPromise, DevicePromise}

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

  def check_promise(promise, dapp_addr) do
    cid = promise["cid"] |> Utils.decode_hex()
    from_binary = promise["from"] |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    to_binary = promise["to"] |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    amount = promise["amount"] |> Utils.decode_hex()
    sign = promise["sign"]

    encode = <<cid::size(256), from_binary::binary, to_binary::binary, amount::size(256)>>

    {:ok, recover_addr} = Crypto.eth_recover(encode, sign)

    if recover_addr == dapp_addr do
      true
    else
      false
    end
  end

  def check_dapp_amount(promise_amount, dapp_addr, server_addr) do
    %{amount: amount} = Contract.bank_allowance(dapp_addr, server_addr)

    if promise_amount <= amount do
      true
    else
      false
    end
  end

  def get_device_promise(promise, dapp_addr, device_addr, addr, private_key) do
    # save promise
    cid = promise["cid"] |> Utils.decode_hex()
    amount = promise["amount"] |> Utils.decode_hex()
    sign = promise["sign"]

    data = DappPromise.get(dapp_addr)

    last_amount =
      if data == nil || data["cid"] != cid do
        0
      else
        data["amount"]
      end

    if amount > last_amount do
      value = %{"cid" => cid, "amount" => amount, "sign" => sign}
      :ok = DappPromise.set(dapp_addr, value)

      # calc device amount
      {_pid, %{cid: device_cid}} = ARP.DevicePool.get(device_addr)
      data = DevicePromise.get(device_addr)

      last_device_amount =
        if data == nil || data["cid"] != device_cid do
          0
        else
          data["amount"]
        end

      device_amount = calc_device_amount(amount, last_amount, last_device_amount)

      # save device promise
      if device_amount > last_device_amount do
        approval_time =
          if data["approval_time"] == nil do
            0
          else
            data["approval_time"]
          end

        info = %{
          "cid" => device_cid,
          "amount" => device_amount,
          "approval_time" => approval_time
        }

        %{amount: current_amount, expired: expired} = Contract.bank_allowance(addr, device_addr)

        approval_amount = Config.get(:device_deposit)
        now = DateTime.utc_now() |> DateTime.to_unix()

        if device_amount > round(current_amount * 0.8) && now - approval_time > 60 do
          Task.start(fn ->
            Contract.bank_increase_approval(private_key, device_addr, approval_amount, expired)
          end)

          info = Map.put(info, "approval_time", now)
          :ok = DevicePromise.set(device_addr, info)
        else
          :ok = DevicePromise.set(device_addr, info)
        end
      end

      # calc device promise
      device_promise =
        calc_device_promise(device_cid, private_key, addr, device_addr, device_amount)

      {:ok, device_promise}
    else
      :error
    end
  end

  defp calc_device_amount(amount, last_amount, last) do
    rate = Config.get(:divide_rate)
    add = round((amount - last_amount) * (1 - rate))
    last + add
  end

  defp calc_device_promise(cid, private_key, server_addr, device_addr, amount) do
    decode_server_addr = server_addr |> String.slice(2..-1) |> Base.decode16!(case: :mixed)
    decode_device_addr = device_addr |> String.slice(2..-1) |> Base.decode16!(case: :mixed)

    data =
      <<cid::size(256), decode_server_addr::binary-size(20), decode_device_addr::binary-size(20),
        amount::size(256)>>

    %{
      cid: cid |> Utils.encode_integer(),
      from: server_addr,
      to: device_addr,
      amount: amount |> Utils.encode_integer(),
      sign: Crypto.eth_sign(data, private_key)
    }
  end
end
