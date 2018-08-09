defmodule ARP.Application do
  @moduledoc false

  use Application

  def start(_type, _args) do
    jsonrpc2_opts = [
      modules: [ARP.API.JSONRPC2.Server, ARP.API.JSONRPC2.Device]
    ]

    children = [
      ARP.API.TCP.Store,
      ARP.Account,
      ARP.Device,
      ARP.DeviceNetSpeed,
      :ranch.child_spec(
        :tcp_device,
        50,
        :ranch_tcp,
        [port: 8000],
        ARP.API.TCP.DeviceProtocol,
        []
      ),
      Plug.Adapters.Cowboy2.child_spec(
        scheme: :http,
        plug: {JSONRPC2.Server.Plug, jsonrpc2_opts},
        options: [port: 4040]
      ),
      ARP.API.JSONRPC2.Nonce
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
