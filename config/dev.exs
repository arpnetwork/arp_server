use Mix.Config

config :arp_server,
  chain_id: 1000,
  token_contract_address: "0x8d39dd6b431bfb065b51fea07b7ee75bef0b53f8",
  registry_contract_address: "0xe1c62093f55e8d7a86198dd8186e6de414b3fae4"

config :ethereumex,
  url: "http://192.168.0.164:8545"

config :os_mon,
  start_cpu_sup: true,
  start_disksup: false,
  start_memsup: true,
  start_os_sup: false
