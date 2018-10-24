use Mix.Config

import_config "#{Mix.env()}.exs"

config :arp_server,
  # fixed config
  data_dir: System.user_home() |> Path.join(".arp_server"),
  base_deposit: 100_000 * round(1.0e18),
  device_deposit: 100 * round(1.0e18),
  divide_rate: 0.05,
  admin_port: 9000
