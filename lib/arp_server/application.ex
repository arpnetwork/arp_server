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
        plug: {JSONRPC2.Servers.HTTP.Plug, ARP.API.JSONRPC2.Handler},
        options: [
          port: 4040,
          ref: ARP.API.JSONRPC2.Handler.HTTP
        ]
      )
    ]

    opts = [strategy: :one_for_one, name: ARP.Supervisor]
    {:ok, pid} = Supervisor.start_link(children, opts)

    # import keystore file
    keystore_dir = Path.expand("~/.arp_server")

    path =
      case check_keystore(keystore_dir) do
        {:ok, file_path} ->
          file_path

        :error ->
          src =
            IO.gets(:stdio, "keystore file don't exist, please input your keystore file path: ")
            |> String.trim_trailing("\n")

          file_name = Path.basename(src)
          des_path = Path.join(keystore_dir, file_name)
          :ok = src |> Path.expand() |> File.cp(des_path)
          des_path
      end

    auth = ExPrompt.password("input your keystore password:") |> String.trim_trailing("\n")

    if ARP.Account.init_key(path, auth) == :ok do
      IO.puts(:stdio, "arp server is running!")
      {:ok, pid}
    else
      IO.puts("keystore file invalid or password error!")
      {:error, :normal}
    end
  end

  defp check_keystore(keystore_dir) do
    with true <- File.exists?(keystore_dir), {:ok, list} <- File.ls(keystore_dir) do
      first = List.first(list)

      if first != nil do
        file_path = Path.join(keystore_dir, first)
        {:ok, file_path}
      else
        :error
      end
    else
      _ ->
        :ok = File.mkdir(keystore_dir)
        :error
    end
  end
end
