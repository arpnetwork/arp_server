use Mix.Config

config :arp_server,
  chain_id: 1000,
  token_contract_address: "0x8d39dd6b431bfb065b51fea07b7ee75bef0b53f8",
  registry_contract_address: "0xeaec0f493d085183541f9130b8c9ee78de8a6fc3",
  bank_contract_address: "0x0bebeedee8ebb75847515efde978c92596366b5d",
  first_registry_block: "0x1"

config :ethereumex,
  url: "http://192.168.0.164:8545"

config :os_mon,
  start_cpu_sup: true,
  start_disksup: false,
  start_memsup: true,
  start_os_sup: false
