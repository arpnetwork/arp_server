defmodule ARP.API.JSONRPC2.Account do
  use JSONRPC2.Server.Handler

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.{Account, DappPromise, Promise, Utils}

  def pay(promise, device_addr, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    with {:ok, dapp_addr} <- Protocol.verify(method(), [promise, device_addr], nonce, sign, addr),
         :ok <- Account.pay(dapp_addr, promise, device_addr) do
      Protocol.response(%{}, nonce, dapp_addr, private_key)
    else
      res ->
        Protocol.response(res)
    end
  end

  def last(cid, sign) do
    decode_cid = Utils.decode_hex(cid)
    private_key = Account.private_key()
    addr = Account.address()

    with {:ok, dapp_addr} <- Protocol.verify(method(), [cid], sign, addr) do
      promise = DappPromise.get(dapp_addr)

      if promise == nil || promise.cid != decode_cid do
        Protocol.response({:error, "Promise not found!"})
      else
        promise =
          promise
          |> Promise.encode()
          |> Poison.encode()

        Protocol.response(%{promise: promise}, dapp_addr, private_key)
      end
    else
      err ->
        Protocol.response(err)
    end
  end
end
