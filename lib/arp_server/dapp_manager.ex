defmodule ARP.DappManager do
  @moduledoc """
  DappManager
  """

  alias ARP.Contract
  alias ARP.DappManager.{Dapp, Pool}

  def get(dapp_addr) do
    Pool.get(dapp_addr)
  end

  def get_all do
    Pool.get_all()
  end

  def get_info(dapp_pid) do
    Dapp.get(dapp_pid)
  end

  def set_info(dapp_addr, ip, port) do
    pid = Pool.get(dapp_addr)
    Dapp.set_info(pid, ip, port)
  end

  def device_offline(dapp_addr, device_addr) do
    pid = Pool.get(dapp_addr)
    Dapp.device_offline(pid, device_addr)
  end

  def load_bound_dapp(server_addr) do
    with {:ok, dapp_list} <- Contract.get_bound_dapp(server_addr) do
      Enum.map(dapp_list, fn dapp_addr ->
        Pool.create(dapp_addr, nil, nil)
      end)
    end
  end

  def check_and_create(dapp_addr) do
    case Pool.get(dapp_addr) do
      nil ->
        case Pool.create(dapp_addr, nil, nil) do
          {:ok, pid} ->
            Dapp.normal?(pid)

          _ ->
            false
        end

      pid ->
        Dapp.normal?(pid)
    end
  end

  def save_promise(pid, promise, increment) do
    Dapp.save_promise(pid, promise, increment)
  end

  def cash(pid) do
    Dapp.cash(pid)
  end
end
