defmodule ARP.API.JSONRPC2.Device do
  @moduledoc false

  use JSONRPC2.Server.Module

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.{Account, DeviceManager, Utils}

  def request(price, ip, port, nonce, sign) do
    decoded_price = Utils.decode_hex(price)

    private_key = Account.private_key()
    addr = Account.address()

    method = Protocol.get_method(__MODULE__, __ENV__)

    with {:ok, dapp_address} <- Protocol.verify(method, [price, ip, port], nonce, sign, addr),
         dev when is_map(dev) <- DeviceManager.request(dapp_address, decoded_price, ip, port) do
      Protocol.response(dev, nonce, dapp_address, private_key)
    else
      err ->
        Protocol.response(err)
    end
  end

  def release(address, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    method = Protocol.get_method(__MODULE__, __ENV__)

    with {:ok, dapp_address} <- Protocol.verify(method, [address], nonce, sign, addr) do
      DeviceManager.release(address, dapp_address)
      Protocol.response(%{}, nonce, dapp_address, private_key)
    else
      err ->
        Protocol.response(err)
    end
  end

  def check_port(tcp_port) do
    ip = Process.get(:remote_ip, {0, 0, 0, 0})
    ip = ip |> Tuple.to_list() |> Enum.join(".") |> to_charlist()

    case DeviceManager.check_port(ip, tcp_port) do
      :ok ->
        Protocol.response(%{})

      :error ->
        Protocol.response(:error)
    end
  end

  def bind(owner_addr, type, sub_addr_list, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    method = Protocol.get_method(__MODULE__, __ENV__)

    with {:ok, ^owner_addr} <-
           Protocol.verify(method, [owner_addr, type, sub_addr_list], nonce, sign, addr),
         {:ok, addr_sign_list} <- Poison.decode(sub_addr_list),
         :ok <- DeviceManager.bind_devices_to_owner(owner_addr, type, addr_sign_list) do
      Protocol.response(%{}, nonce, owner_addr, private_key)
    else
      err ->
        Protocol.response(err)
    end
  end

  def check_bind(device_addr, sub_addr) do
    if DeviceManager.is_bind?(device_addr, sub_addr) do
      Protocol.response(%{})
    else
      Protocol.response(:error)
    end
  end
end
