use Mix.Config

config :arp_server,
  chain_id: 1000,
  token_contract_address: "0x8d39dd6b431bfb065b51fea07b7ee75bef0b53f8",
  registry_contract_address: "0x9f6b469dd5ec3e86f19cac817a2bc802ae54520d",
  bank_contract_address: "0x19ea440d8a78a06be54ffca6a8564197bd1b443a",
  first_registry_block: "0x1"

config :ethereumex,
  url: "http://192.168.0.164:8545"

config :os_mon,
  start_cpu_sup: true,
  start_disksup: false,
  start_memsup: true,
  start_os_sup: false
