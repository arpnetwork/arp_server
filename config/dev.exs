use Mix.Config

config :arp_server,
  chain_id: 1000,
  token_contract_address: "0xe1c62093f55e8d7a86198dd8186e6de414b3fae4",
  registry_contract_address: "0xf806be137e1b3b8a8bd324873fe63ec70c78c139",
  bank_contract_address: "0x2d240cfa28c9d3702acd77425d0a12fa41dda35a",
  first_registry_block: "0x1"

config :ethereumex,
  url: "http://localhost:8545"

config :os_mon,
  start_cpu_sup: true,
  start_disksup: false,
  start_memsup: true,
  start_os_sup: false
