use Mix.Config

config :arp_server,
  chain_id: 1,
  contract_address: "0xbeb6fdf4ef6ceb975157be43cbe0047b248a8922"

config :ethereumex,
  url: ""

config :os_mon,
  start_cpu_sup: true,
  start_disksup: false,
  start_memsup: true,
  start_os_sup: false