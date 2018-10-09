defmodule ARP.API.JSONRPC2.Server do
  @moduledoc false

  use JSONRPC2.Server.Handler

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.{Account, Server}

  def info do
    Protocol.response(Server.info())
  end

  def bind_promise(spender) do
    private_key = Account.private_key()

    case Server.get_bind_promise(spender) do
      {:ok, resp} ->
        Protocol.response(resp, spender, private_key)

      :error ->
        Protocol.response({:error, "get bind promise faild!"})
    end
  end
end
