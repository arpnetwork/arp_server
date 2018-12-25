defmodule ARP.API.JSONRPC2.Nonce do
  @moduledoc false

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.{Account, Nonce, Utils}

  use JSONRPC2.Server.Module

  def get(address) do
    self_addr = Account.address()
    nonce = Nonce.get(address, self_addr)

    Protocol.response(%{nonce: Utils.encode_integer(nonce)})
  end
end
