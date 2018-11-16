defmodule ARP.API.JSONRPC2.Device do
  @moduledoc false

  use JSONRPC2.Server.Handler

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.{Account, Crypto, Device, DeviceBind, DevicePool, Utils}

  def request(price, ip, port, nonce, sign) do
    decoded_price = Utils.decode_hex(price)

    private_key = Account.private_key()
    addr = Account.address()

    with {:ok, dapp_address} <- Protocol.verify(method(), [price, ip, port], nonce, sign, addr),
         dev when is_map(dev) <- DevicePool.request(dapp_address, decoded_price, ip, port) do
      Protocol.response(dev, nonce, dapp_address, private_key)
    else
      err ->
        Protocol.response(err)
    end
  end

  def release(address, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    with {:ok, dapp_address} <- Protocol.verify(method(), [address], nonce, sign, addr) do
      DevicePool.release(address, dapp_address)
      Protocol.response(%{}, nonce, dapp_address, private_key)
    else
      err ->
        Protocol.response(err)
    end
  end

  def check_port(tcp_port) do
    ip = Process.get(:remote_ip, {0, 0, 0, 0})
    ip = ip |> Tuple.to_list() |> Enum.join(".") |> to_charlist()

    case Device.check_port(ip, tcp_port) do
      :ok ->
        Protocol.response(%{})

      :error ->
        Protocol.response(:error)
    end
  end

  def bind(device_addr, type, sub_addr_list, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    with {:ok, ^device_addr} <-
           Protocol.verify(method(), [device_addr, type, sub_addr_list], nonce, sign, addr),
         {:ok, addr_sign_list} <- Poison.decode(sub_addr_list),
         :ok <- Device.check_device_allowance(device_addr, type, length(addr_sign_list)),
         true <-
           Enum.all?(addr_sign_list, fn item ->
             {:ok, decode_sub_addr} = Crypto.eth_recover(item["salt"], item["sub_sign"])

             if decode_sub_addr == item["sub_addr"] do
               true
             else
               false
             end
           end) do
      list = Enum.map(addr_sign_list, fn item -> item["sub_addr"] end)

      case type do
        1 ->
          DeviceBind.delete_all_and_add_sub_device(device_addr, list)
          Protocol.response(%{}, nonce, device_addr, private_key)

        2 ->
          DeviceBind.add_sub_device(device_addr, list)
          Protocol.response(%{}, nonce, device_addr, private_key)

        _ ->
          Protocol.response(:error)
      end
    else
      {:ok, _} ->
        Protocol.response({:error, "Invalid sign 2"})

      false ->
        Protocol.response({:error, "Invalid sub_sign"})

      err ->
        Protocol.response(err)
    end
  end

  def check_bind(device_addr, sub_addr) do
    if DeviceBind.is_bind?(device_addr, sub_addr) do
      Protocol.response(%{})
    else
      Protocol.response(:error)
    end
  end
end
