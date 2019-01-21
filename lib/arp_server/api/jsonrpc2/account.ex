defmodule ARP.API.JSONRPC2.Account do
  @moduledoc false

  use JSONRPC2.Server.Module

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.{Account, Utils}

  def pay(promise, amount, device_addr, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    method = Protocol.get_method(__MODULE__, __ENV__)

    with {:ok, dapp_addr} <-
           Protocol.verify(method, [promise, amount, device_addr], nonce, sign, addr),
         :ok <- Account.pay(dapp_addr, promise, Utils.decode_hex(amount), device_addr) do
      Protocol.response(%{}, nonce, dapp_addr, private_key)
    else
      res ->
        Protocol.response(res)
    end
  end

  def last(cid, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    method = Protocol.get_method(__MODULE__, __ENV__)

    with {:ok, dapp_addr} <- Protocol.verify(method, [cid], sign, addr) do
      promise = Account.get_dapp_promise(dapp_addr, true)

      if promise == nil || promise.cid != cid do
        Protocol.response({:error, :promise_not_found})
      else
        Protocol.response(%{promise: Poison.encode!(promise)}, dapp_addr, private_key)
      end
    else
      err ->
        Protocol.response(err)
    end
  end
end
