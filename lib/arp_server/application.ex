defmodule ARP.Application do
  @moduledoc false

  use Application

  def start(_type, _args) do
    children = [
      ARP.API.TCP.Store,
      ARP.Account,
      ARP.DeviceManager,
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
        plug: ARP.API.HTTP.Router,
        options: [port: 4040]
      )
    ]

    opts = [strategy: :one_for_one, name: ARP.Supervisor]
    {:ok, pid} = Supervisor.start_link(children, opts)

    # import keystore file
    auth = ExPrompt.password("input your keystore password:") |> String.trim_trailing("\n")

    if ARP.Account.init_key(auth) == :ok do
      IO.puts(:stdio, "arp server is running!")
      {:ok, pid}
    else
      IO.puts("keystore file invalid or password error!")
      {:error, :normal}
    end
  end
end
