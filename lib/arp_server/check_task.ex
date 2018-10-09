defmodule ARP.CheckTask do
  @moduledoc false

  alias ARP.{Account, Contract, DevicePromise}

  use Task, restart: :permanent

  require Logger

  def start_link(_arg) do
    Task.start_link(__MODULE__, :run, [])
  end

  def run do
    loop_time = 1000 * 60 * 60
    Process.sleep(loop_time)

    private_key = Account.private_key()
    server_addr = Account.address()

    # get device bind list
    with {:ok, device_list} <- Contract.get_bound_device(server_addr) do
      # check device bind expired
      Enum.each(device_list, fn device_addr ->
        check_device_bind(device_addr, private_key, server_addr)
      end)

      # check server unregister expired
      check_server_unregister(private_key, server_addr, device_list)
    end

    run()
  end

  defp check_device_bind(device_addr, private_key, server_addr) do
    now = DateTime.utc_now() |> DateTime.to_unix()

    with {:ok, %{server: server, expired: expired}} <- Contract.get_device_bind_info(device_addr) do
      if server == server_addr && expired != 0 && expired < now do
        Task.start(fn -> Contract.unbind_device_by_server(private_key, device_addr) end)
        DevicePromise.delete(device_addr)
      end
    end
  end

  defp check_server_unregister(private_key, server_addr, device_list) do
    now = DateTime.utc_now() |> DateTime.to_unix()

    with {:ok, %{ip: ip, expired: expired, size: size}} <-
           Contract.get_registered_info(server_addr) do
      if ip != 0 && expired != 0 && now > expired do
        if size == 0 do
          Task.start(fn ->
            with {:ok, %{"status" => "0x1"}} <- Contract.unregister(private_key),
                 {:ok, value} <- Contract.bank_balance(server_addr),
                 {:ok, %{"status" => "0x1"}} <- Contract.bank_withdraw(private_key, value) do
              Logger.info("unregister success, withdraw ARP to wallet from ARP Bank.")
            else
              e ->
                Logger.error("unregister error")
                Logger.error(inspect(e))
            end
          end)
        else
          Enum.each(device_list, fn device_addr ->
            with {:ok, %{server: server, expired: device_expired}} <-
                   Contract.get_device_bind_info(device_addr) do
              if server == server_addr && device_expired == 0 do
                Task.start(fn ->
                  Contract.unbind_device_by_server(private_key, device_addr)
                end)
              end
            end
          end)
        end
      end
    end
  end
end
