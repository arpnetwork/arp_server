defmodule ARP.Application do
  @moduledoc false

  use Application

  def start(_type, _args) do
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
        plug: {JSONRPC2.Servers.HTTP.Plug, ARP.API.JSONRPC2.Handler},
        options: [
          port: 4040,
          ref: ARP.API.JSONRPC2.Handler.HTTP
        ]
      )
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
