defmodule ARP.Application do
  @moduledoc false

  use Application

  @tcp_port Application.get_env(:arp_server, :port)
  @jsonrpc_port @tcp_port + 1

  def start(_type, _args) do
    jsonrpc2_opts = [
      modules: [ARP.API.JSONRPC2.Server, ARP.API.JSONRPC2.Device, ARP.API.JSONRPC2.Account]
    ]

    ARP.Nonce.init()

    children = [
      ARP.Config,
      ARP.API.TCP.Store,
      ARP.Account,
      ARP.Device,
      ARP.DeviceNetSpeed,
      ARP.DappPromise,
      ARP.DevicePromise,
      :ranch.child_spec(
        :tcp_device,
        50,
        :ranch_tcp,
        [port: @tcp_port],
        ARP.API.TCP.DeviceProtocol,
        []
      ),
      Plug.Adapters.Cowboy2.child_spec(
        scheme: :http,
        plug: {JSONRPC2.Server.Plug, jsonrpc2_opts},
        options: [port: @jsonrpc_port]
      ),
      ARP.API.JSONRPC2.Nonce,
      ARP.CheckTask
    ]

    opts = [strategy: :one_for_one, name: ARP.Supervisor]
    {:ok, pid} = Supervisor.start_link(children, opts)

    # initialize
    case ARP.Init.init() do
      :ok ->
        {:ok, pid}

      :error ->
        {:error, :normal}
    end
  end
end
