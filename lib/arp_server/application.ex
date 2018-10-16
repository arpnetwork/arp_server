defmodule ARP.Application do
  @moduledoc false

  alias Plug.Adapters.Cowboy2
  alias ARP.{DappPool, Init}

  use Application

  @tcp_port Application.get_env(:arp_server, :port)
  @jsonrpc_port @tcp_port + 1

  def start(_type, _args) do
    jsonrpc2_opts = [
      modules: [
        ARP.API.JSONRPC2.Server,
        ARP.API.JSONRPC2.Device,
        ARP.API.JSONRPC2.Account,
        ARP.API.JSONRPC2.Nonce
      ]
    ]

    children = [
      {DynamicSupervisor, strategy: :one_for_one, name: ARP.DynamicSupervisor},
      ARP.Config,
      ARP.Nonce,
      ARP.Account,
      ARP.DevicePool,
      ARP.DeviceNetSpeed,
      ARP.DappPromise,
      ARP.DappPool,
      ARP.DevicePromise,
      :ranch.child_spec(
        :tcp_device,
        50,
        :ranch_tcp,
        [port: @tcp_port],
        ARP.API.TCP.DeviceProtocol,
        []
      ),
      Cowboy2.child_spec(
        scheme: :http,
        plug: {JSONRPC2.Server.Plug, jsonrpc2_opts},
        options: [port: @jsonrpc_port]
      ),
      ARP.CheckTask
    ]

    opts = [strategy: :one_for_one, name: ARP.Supervisor]
    {:ok, pid} = Supervisor.start_link(children, opts)

    # initialize
    case Init.init() do
      :ok ->
        DappPool.load_bound_dapp()
        {:ok, pid}

      :error ->
        {:error, :normal}
    end
  end
end
