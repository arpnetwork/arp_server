defmodule ARP.API.JSONRPC2.Server do
  use JSONRPC2.Server.Handler

  alias ARP.API.JSONRPC2.Protocol

  def info() do
    Protocol.response(ARP.Server.info())
  end
end
