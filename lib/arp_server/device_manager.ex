defmodule ARP.DeviceManager do
  @moduledoc """
  DeviceManager
  """

  alias ARP.DeviceManager.{Allowance, Device, Owner, Pool, SpeedTester}

  def create(data) do
    struct(Device, data)
  end

  def get(device_addr) do
    Pool.get(device_addr)
  end

  def get_all do
    Pool.get_all()
  end

  def request(dapp_address, price, ip, port) do
    Pool.request(dapp_address, price, ip, port)
  end

  def release(address, dapp_address) do
    Pool.release(address, dapp_address)
  end

  def release_by_dapp(dapp_address) do
    Pool.release_by_dapp(dapp_address)
  end

  def idle(device_addr) do
    Pool.idle(device_addr)
  end

  def size do
    Pool.size()
  end

  def get_device_size(owner_addr) do
    Pool.get_device_size(owner_addr)
  end

  def get_by_dapp(dapp_address) do
    Pool.get_by_dapp(dapp_address)
  end

  def get_by_tcp_pid(tcp_pid) do
    Pool.get_by_tcp_pid(tcp_pid)
  end

  def online(device) do
    Pool.online(device)
  end

  # sub_addr
  def offline(device_addr) do
    Pool.offline(device_addr)
  end

  def test_speed(ip, device_addr, tcp_pid) do
    SpeedTester.online(ip, device_addr, tcp_pid)
  end

  def set_speed(ip, ul_speed, dl_speed) do
    SpeedTester.set(ip, ul_speed, dl_speed)
  end

  def check_port(host, tcp_port) do
    Device.check_port(host, tcp_port)
  end

  def get_all_owner do
    Owner.get_all()
  end

  def get_owner_address(device_addr) do
    Owner.get_owner_address(device_addr)
  end

  def bind_devices_to_owner(owner_addr, type, addr_sign_list) do
    Owner.bind_devices(owner_addr, type, addr_sign_list)
  end

  def is_bind?(device_addr, sub_addr) do
    Owner.has(device_addr, sub_addr)
  end

  def check_allowance(device_addr, amount) do
    Allowance.check(device_addr, amount)
  end
end
