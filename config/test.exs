use Mix.Config

config :arp_server,
  chain_id: 10,
  token_contract_address: "0x8d39dd6b431bfb065b51fea07b7ee75bef0b53f8",
  registry_contract_address: "0xe1c62093f55e8d7a86198dd8186e6de414b3fae4",
  bank_contract_address: "0x0bebeedee8ebb75847515efde978c92596366b5d",
  first_registry_block: "0x1"

config :ethereumex,
  url: "http://localhost:8545"
