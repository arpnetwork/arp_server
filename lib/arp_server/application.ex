defmodule ARP.Application do
  @moduledoc false

  use Application

  def start(_type, _args) do
    data_path = Path.join(System.user_home(), Application.get_env(:arp_server, :data_dir))

    unless File.exists?(data_path) do
      File.mkdir_p!(data_path)
    end

    ARP.Admin.init()

    children = [
      {DynamicSupervisor, strategy: :one_for_one, name: ARP.DynamicSupervisor},
      {ARP.Config, data_path: data_path},
      ARP.Nonce,
      ARP.Account,
      ARP.DevicePool,
      ARP.DeviceNetSpeed,
      ARP.DappPromise,
      ARP.DappPool,
      ARP.DevicePromise,
      ARP.Service,
      ARP.DeviceBind,
      Plug.Cowboy.child_spec(
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
