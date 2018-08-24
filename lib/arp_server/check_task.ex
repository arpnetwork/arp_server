defmodule ARP.CheckTask do
  use Task, restart: :permanent

  def start_link(_arg) do
    Task.start_link(__MODULE__, :run, [])
  end

  def run() do
    loop_time = 1000 * 60 * 60
    Process.sleep(loop_time)

    {:ok, %{private_key: private_key, addr: server_addr}} = ARP.Account.get_info()

    # check dapp promise expired
    info = ARP.DappPromise.get_all()
    Enum.each(info, fn {k, v} -> check_dapp_approval(k, v, private_key, server_addr) end)

    # get device bind list
    device_list = ARP.Contract.get_bound_device(server_addr)

    # check device bind expired
    Enum.each(device_list, fn device_addr ->
      check_device_bind(device_addr, private_key, server_addr)
    end)

    run()
  end

  defp check_dapp_approval(dapp_addr, info, private_key, server_addr) do
    %{id: cid, paid: paid, expired: expired} = ARP.Contract.bank_allowance(dapp_addr, server_addr)

    check_time = (DateTime.utc_now() |> DateTime.to_unix()) + 60 * 60 * 24

    if info["cid"] == cid && info["amount"] > paid && expired != 0 && expired < check_time do
      Task.start(fn ->
        ARP.Contract.bank_cash(private_key, dapp_addr, server_addr, info["amount"], info["sign"])
      end)
    end
  end

  defp check_device_bind(device_addr, private_key, server_addr) do
    %{server: server, expired: expired} = ARP.Contract.get_device_bind_info(device_addr)

    now = DateTime.utc_now() |> DateTime.to_unix()

    if server == server_addr && expired != 0 && expired < now do
      Task.start(fn -> ARP.Contract.unbind_device_by_server(private_key, device_addr) end)
    end
  end
end
