defmodule ARP.API.JSONRPC2.Device do
  @moduledoc false

  use JSONRPC2.Server.Handler

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.{Account, Device, DevicePool, Utils}

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
end
