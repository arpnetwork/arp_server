use Mix.Config

import_config "#{Mix.env()}.exs"

config :arp_server,
  bandwidth: 100,
  keystore_file:
    "~/Downloads/UTC--2018-07-27T09-40-19.671Z--c52ee303d9077bd9e66847237a111ed0c229911c",
  ip: "192.168.0.159",
  port: 8000,
  approve: 600_000 * round(1.0e18),
  amount: 100 * round(1.0e18),
  divide_rate: 0.05
