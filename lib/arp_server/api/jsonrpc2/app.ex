defmodule ARP.API.JSONRPC2.App do
  @moduledoc false

  use JSONRPC2.Server.Handler

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.API.TCP.DeviceProtocol
  alias ARP.{Account, DevicePool}

  def install(device_addr, package, url, filesize, md5, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    with {:ok, dapp_addr} <-
           Protocol.verify(
             method(),
             [device_addr, package, url, filesize, md5],
             nonce,
             sign,
             addr
           ),
         {_, %{tcp_pid: tcp_pid, dapp_address: ^dapp_addr}} <- DevicePool.get(device_addr) do
      DeviceProtocol.app_install(tcp_pid, package, url, filesize, md5)
      Protocol.response(%{}, nonce, dapp_addr, private_key)
    else
      err ->
        Protocol.response(err)
    end
  end

  def uninstall(device_addr, package, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    with {:ok, dapp_addr} <- Protocol.verify(method(), [device_addr, package], nonce, sign, addr),
         {_, %{tcp_pid: tcp_pid, dapp_address: ^dapp_addr}} <- DevicePool.get(device_addr) do
      DeviceProtocol.app_uninstall(tcp_pid, package)
      Protocol.response(%{}, nonce, dapp_addr, private_key)
    else
      err ->
        Protocol.response(err)
    end
  end

  def start(device_addr, package, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    with {:ok, dapp_addr} <- Protocol.verify(method(), [device_addr, package], nonce, sign, addr),
         {_, %{tcp_pid: tcp_pid, dapp_address: ^dapp_addr}} <- DevicePool.get(device_addr) do
      DeviceProtocol.app_start(tcp_pid, package)
      Protocol.response(%{}, nonce, dapp_addr, private_key)
    else
      err ->
        Protocol.response(err)
    end
  end
end
