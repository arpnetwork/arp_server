defmodule ARP.CheckTask do
  use Task, restart: :permanent

  def start_link(_arg) do
    Task.start_link(__MODULE__, :run, [])
  end

  def run() do
    loop_time = 1000 * 60 * 60
    Process.sleep(loop_time)

    private_key = ARP.Account.private_key()
    server_addr = ARP.Account.address()

    # get device bind list
    device_list = ARP.Contract.get_bound_device(server_addr)

    # check device bind expired
    Enum.each(device_list, fn device_addr ->
      check_device_bind(device_addr, private_key, server_addr)
    end)

    # check server unregister expired
    check_server_unregister(private_key, server_addr, device_list)

    run()
  end

  defp check_device_bind(device_addr, private_key, server_addr) do
    %{server: server, expired: expired} = ARP.Contract.get_device_bind_info(device_addr)

    now = DateTime.utc_now() |> DateTime.to_unix()

    if server == server_addr && expired != 0 && expired < now do
      Task.start(fn -> ARP.Contract.unbind_device_by_server(private_key, device_addr) end)
      ARP.DevicePromise.delete(device_addr)
    end
  end

  defp check_server_unregister(private_key, server_addr, device_list) do
    now = DateTime.utc_now() |> DateTime.to_unix()

    %{ip: ip, expired: expired, size: size} = ARP.Contract.get_registered_info(server_addr)

    if ip != 0 && expired != 0 && now > expired do
      if size == 0 do
        Task.start(fn -> ARP.Contract.unregister(private_key) end)
      else
        Enum.each(device_list, fn device_addr ->
          %{server: server, expired: device_expired} =
            ARP.Contract.get_device_bind_info(device_addr)

          if server == server_addr && device_expired == 0 do
            Task.start(fn -> ARP.Contract.unbind_device_by_server(private_key, device_addr) end)
          end
        end)
      end
    end
  end
end
