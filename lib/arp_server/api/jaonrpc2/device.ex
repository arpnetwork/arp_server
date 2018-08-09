defmodule ARP.API.JSONRPC2.Device do
  use JSONRPC2.Server.Handler

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.Account
  alias ARP.Utils

  def request(price, ip, port, nonce, sign) do
    decoded_price = Utils.decode_hex(price)

    {:ok, self_info} = Account.get_info()

    with {:ok, dapp_address} <-
           Protocol.verify(method(), [price, ip, port], nonce, sign, self_info.addr),
         dev when is_map(dev) <- ARP.Device.request(dapp_address, decoded_price, ip, port) do
      Protocol.response(dev, nonce, dapp_address, self_info.private_key)
    else
      err ->
        Protocol.response(err)
    end
  end
end
