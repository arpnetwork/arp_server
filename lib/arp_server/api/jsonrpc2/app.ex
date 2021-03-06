defmodule ARP.API.JSONRPC2.App do
  @moduledoc false

  use JSONRPC2.Server.Module

  alias ARP.API.JSONRPC2.Protocol
  alias ARP.API.TCP.DeviceProtocol
  alias ARP.{Account, DeviceManager}

  def install(device_addr, package, url, filesize, md5, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    method = Protocol.get_method(__MODULE__, __ENV__)

    with {:ok, dapp_addr} <-
           Protocol.verify(
             method,
             [device_addr, package, url, filesize, md5],
             nonce,
             sign,
             addr
           ),
         {_, %{tcp_pid: tcp_pid, dapp_address: ^dapp_addr}} <- DeviceManager.get(device_addr) do
      DeviceProtocol.app_install(tcp_pid, 0, package, url, filesize, md5)
      Protocol.response(%{}, nonce, dapp_addr, private_key)
    else
      _ ->
        Protocol.response(:error)
    end
  end

  def install(device_addr, mode, package, url, filesize, md5, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    method = Protocol.get_method(__MODULE__, __ENV__)

    with {:ok, dapp_addr} <-
           Protocol.verify(
             method,
             [device_addr, mode, package, url, filesize, md5],
             nonce,
             sign,
             addr
           ),
         {_, %{tcp_pid: tcp_pid, dapp_address: ^dapp_addr}} <- DeviceManager.get(device_addr) do
      DeviceProtocol.app_install(tcp_pid, mode, package, url, filesize, md5)
      Protocol.response(%{}, nonce, dapp_addr, private_key)
    else
      _ ->
        Protocol.response(:error)
    end
  end

  def uninstall(device_addr, package, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    method = Protocol.get_method(__MODULE__, __ENV__)

    with {:ok, dapp_addr} <- Protocol.verify(method, [device_addr, package], nonce, sign, addr),
         {_, %{tcp_pid: tcp_pid, dapp_address: ^dapp_addr}} <- DeviceManager.get(device_addr) do
      DeviceProtocol.app_uninstall(tcp_pid, package)
      Protocol.response(%{}, nonce, dapp_addr, private_key)
    else
      _ ->
        Protocol.response(:error)
    end
  end

  def start(device_addr, package, nonce, sign) do
    private_key = Account.private_key()
    addr = Account.address()

    method = Protocol.get_method(__MODULE__, __ENV__)

    with {:ok, dapp_addr} <- Protocol.verify(method, [device_addr, package], nonce, sign, addr),
         {_, %{tcp_pid: tcp_pid, dapp_address: ^dapp_addr}} <- DeviceManager.get(device_addr) do
      DeviceProtocol.app_start(tcp_pid, package)
      DeviceProtocol.check_app_start(tcp_pid, package)
      Protocol.response(%{}, nonce, dapp_addr, private_key)
    else
      _ ->
        Protocol.response(:error)
    end
  end
end
