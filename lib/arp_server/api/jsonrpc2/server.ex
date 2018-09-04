defmodule ARP.API.JSONRPC2.Server do
  use JSONRPC2.Server.Handler

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.Account

  def info() do
    Protocol.response(ARP.Server.info())
  end

  def bind_promise(spender) do
    private_key = Account.private_key()

    case ARP.Server.get_bind_promise(spender) do
      {:ok, resp} ->
        Protocol.response(resp, spender, private_key)

      :error ->
        Protocol.response({:error, "get bind promise faild!"})
    end
  end
end
