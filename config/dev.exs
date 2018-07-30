use Mix.Config

config :arp_server,
  chain_id: 10,
  contract_address: "0x9d158a79804e451bb1d7b1d87ebb7a5804e636d2"

config :ethereumex,
  url: "http://localhost:8545"

config :os_mon,
  start_cpu_sup: true,
  start_disksup: false,
  start_memsup: true,
  start_os_sup: false
