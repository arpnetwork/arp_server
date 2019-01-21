defmodule ARP.Service do
  @moduledoc """
  Service supervisor
  """

  alias ARP.API.JSONRPC2.{Account, App, Device, Nonce, Server}
  alias ARP.API.TCP.DeviceProtocol
  alias ARP.{CheckTask, Config, DeviceManager}

  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def start_service do
    GenServer.call(__MODULE__, :start_service)
  end

  def stop_service do
    GenServer.cast(__MODULE__, :stop_service)
  end

  def init(_arg) do
    {:ok, pid} = DynamicSupervisor.start_link(strategy: :one_for_one, name: :dynamic_services)
    {:ok, %{pid: pid}}
  end

  def handle_call(:start_service, _from, %{pid: pid} = state) do
    tcp_port = Config.get(:port)
    jsonrpc_port = tcp_port + 1

    # tcp service
    tcp_spec =
      :ranch.child_spec(
        :tcp_device,
        50,
        :ranch_tcp,
        [port: tcp_port],
        DeviceProtocol,
        []
      )

    # start jsonrpc service
    jsonrpc2_opts = {JSONRPC2.Server.ModuleHandler, [Server, Device, Account, Nonce, App]}

    jsonrpc_spec =
      Plug.Cowboy.child_spec(
        scheme: :http,
        plug: {JSONRPC2.Server.Plug, jsonrpc2_opts},
        options: [port: jsonrpc_port]
      )

    # start check timer
    check_task_spec = CheckTask

    res =
      with {:ok, _} <- DynamicSupervisor.start_child(pid, tcp_spec),
           {:ok, _} <- DynamicSupervisor.start_child(pid, jsonrpc_spec),
           {:ok, _} <- DynamicSupervisor.start_child(pid, check_task_spec) do
        :ok
      else
        err ->
          stop_service()
          err
      end

    {:reply, res, state}
  end

  def handle_cast(:stop_service, %{pid: pid} = state) do
    # offline all device
    devices = DeviceManager.get_all()

    Enum.each(devices, fn {_, _, dev} ->
      DeviceManager.offline(dev.address)
    end)

    # stop all service
    children = DynamicSupervisor.which_children(pid)

    Enum.each(children, fn {_, child, _, _} ->
      if child != :restarting do
        DynamicSupervisor.terminate_child(pid, child)
      end
    end)

    {:noreply, state}
  end
end
