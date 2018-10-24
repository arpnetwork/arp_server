defmodule ARP.Application do
  @moduledoc false

  use Application

  def start(_type, _args) do
    ARP.Admin.init()

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
      ARP.Service,
      Plug.Adapters.Cowboy2.child_spec(
        scheme: :http,
        plug: ARP.API.HTTP.Router,
        options: [
          port: Application.get_env(:arp_server, :admin_port)
        ]
      )
    ]

    opts = [strategy: :one_for_one, name: ARP.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
