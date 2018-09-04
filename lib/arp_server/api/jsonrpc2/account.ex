defmodule ARP.API.JSONRPC2.Account do
  use JSONRPC2.Server.Handler

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.{Account, Utils, DevicePromise}

  def pay(promise, device_addr, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    with {:ok, dapp_addr} <- Protocol.verify(method(), [promise, device_addr], nonce, sign, addr),
         {:ok, promise} <- Poison.decode(promise),
         true <- Account.check_promise(promise, dapp_addr),
         true <-
           Account.check_dapp_amount(promise["amount"] |> Utils.decode_hex(), dapp_addr, addr) do
      case Account.get_device_promise(promise, dapp_addr, device_addr, addr, private_key) do
        {:ok, device_promise} ->
          # send device promise to device
          DevicePromise.account_pay(device_addr, Poison.encode!(device_promise))

          Protocol.response(%{}, nonce, dapp_addr, private_key)

        :error ->
          Protocol.response({:error, "amount error!"})
      end
    else
      _ ->
        Protocol.response({:error, "promise error!"})
    end
  end

  def last(cid, sign) do
    decode_cid = Utils.decode_hex(cid)
    private_key = Account.private_key()
    addr = Account.address()

    with {:ok, dapp_addr} <- Protocol.verify(method(), [cid], sign, addr) do
      info = ARP.DappPromise.get(dapp_addr)

      if info == nil || info["cid"] != decode_cid do
        Protocol.response({:error, "Promise not found!"})
      else
        promise =
          %{
            cid: cid,
            from: dapp_addr,
            to: addr,
            amount: Utils.encode_integer(info["amount"]),
            sign: info["sign"]
          }
          |> Poison.encode!()

        Protocol.response(%{promise: promise}, dapp_addr, private_key)
      end
    else
      _ ->
        Protocol.response({:error, "get last promise error!"})
    end
  end
end
