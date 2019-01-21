defmodule ARP.Account do
  @moduledoc """
  Manage server account
  """

  alias ARP.Account.{Keystore, Promise}
  alias ARP.API.TCP.DeviceProtocol
  alias ARP.{Config, DappManager, DeviceManager, Utils}

  require Logger

  def address do
    Keystore.address()
  end

  def private_key do
    Keystore.private_key()
  end

  def exists? do
    Keystore.exists?()
  end

  def set_key(keystore, password) do
    Keystore.set(keystore, password)
  end

  def get_device_promise(address, encoded \\ false) do
    promise = Promise.get_device(address)

    if encoded do
      Promise.encode(promise)
    else
      promise
    end
  end

  def get_all_device_promise do
    Promise.get_all_device()
  end

  def get_dapp_promise(address, encoded \\ false) do
    promise = Promise.get_dapp(address)

    if encoded do
      Promise.encode(promise)
    else
      promise
    end
  end

  def get_all_dapp_promise do
    Promise.get_all_dapp()
  end

  def delete_device_promise(address) do
    Promise.delete_device(address)
  end

  def delete_dapp_promise(address) do
    Promise.delete_dapp(address)
  end

  def set_device_promise(address, promise) do
    Promise.set_device(address, promise)
  end

  def set_dapp_promise(address, promise) do
    Promise.set_dapp(address, promise)
  end

  def create_promise(private_key, cid, from, to, amount, paid \\ 0) do
    Promise.create(private_key, cid, from, to, amount, paid)
  end

  def verify_promise(promise, cid, from, to) do
    with false <- is_nil(promise),
         true <- Promise.verify(promise, cid, from, to) do
      true
    else
      _ -> false
    end
  end

  def encode_promise(promise) do
    Promise.encode(promise)
  end

  def decode_promise(promise) do
    Promise.decode(promise)
  end

  def pay(dapp_addr, promise, increment, sub_addr) do
    self_addr = Keystore.address()
    private_key = Keystore.private_key()

    with {:ok, promise} <- Poison.decode(promise, as: %Promise{}),
         true <- Promise.verify(promise, dapp_addr, self_addr),
         promise = Promise.decode(promise),
         dapp_pid when not is_nil(dapp_pid) <- DappManager.get(dapp_addr),
         :ok <- DappManager.save_promise(dapp_pid, promise, increment),
         device_addr when not is_nil(device_addr) <- DeviceManager.get_owner_address(sub_addr),
         device_promise =
           calc_device_promise(increment, device_addr, sub_addr, self_addr, private_key),
         true <- check_device_amount(device_addr, device_promise.amount) do
      set_device_promise(device_addr, device_promise)

      with {_, dev} <- DeviceManager.get(sub_addr) do
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

  defp check_device_amount(device_addr, amount) do
    with :ok <- DeviceManager.check_allowance(device_addr, amount) do
      true
    else
      e ->
        Logger.debug(fn -> inspect(e) end, label: "check device amount")
        false
    end
  end

  defp calc_device_promise(incremental_amount, device_addr, sub_addr, server_addr, private_key) do
    # calc device amount and promise
    {_pid, %{cid: device_cid}} = DeviceManager.get(sub_addr)
    device_promise = get_device_promise(device_addr)

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
