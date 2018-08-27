use Mix.Config

import_config "#{Mix.env()}.exs"

config :arp_server,
  data_dir: System.user_home() |> Path.join(".arp_server"),
  port: 8000,
  approve: 600_000 * round(1.0e18),
  amount: 100 * round(1.0e18),
  divide_rate: 0.05,
  keystore_file: nil,
  ip: nil,
  bandwidth: nil
