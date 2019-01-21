defmodule ARP.Application do
  @moduledoc false

  alias ARP.Admin
  alias ARP.API.HTTP.Router

  use Application

  def start(_type, _args) do
    data_path = Path.join(System.user_home(), Application.get_env(:arp_server, :data_dir))

    unless File.exists?(data_path) do
      File.mkdir_p!(data_path)
    end

    Admin.init()

    children = [
      {ARP.Config, data_path: data_path},
      ARP.Nonce,
      ARP.Account.Supervisor,
      ARP.DeviceManager.Supervisor,
      ARP.DappManager.Supervisor,
      ARP.Service,
      Plug.Cowboy.child_spec(
        scheme: :http,
        plug: Router,
        options: [
          port: Application.get_env(:arp_server, :admin_port)
        ]
      )
    ]

    opts = [strategy: :one_for_one, name: ARP.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
