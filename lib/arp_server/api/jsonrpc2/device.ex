defmodule ARP.API.JSONRPC2.Device do
  use JSONRPC2.Server.Handler

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.Account
  alias ARP.Utils

  def request(price, ip, port, nonce, sign) do
    decoded_price = Utils.decode_hex(price)

    private_key = Account.private_key()
    addr = Account.address()

    with {:ok, dapp_address} <- Protocol.verify(method(), [price, ip, port], nonce, sign, addr),
         dev when is_map(dev) <- ARP.DevicePool.request(dapp_address, decoded_price, ip, port) do
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
      ARP.DevicePool.release(address, dapp_address)
      Protocol.response(%{}, nonce, dapp_address, private_key)
    else
      err ->
        Protocol.response(err)
    end
  end
end
