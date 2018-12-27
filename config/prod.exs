use Mix.Config

config :arp_server,
  chain_id: 1000,
  token_contract_address: "0x385f501f44c7f2bdf548254bd4093a7363408192",
  registry_contract_address: "0x9933a36af379dca919b480673c5f6ee55fc85209",
  bank_contract_address: "0x5ef53235f67aef7781850d50ce49ec8de3597286",
  first_registry_block: "0x1"

config :ethereumex,
  url: "http://dev.arpnetwork.org:8545"

config :logger,
  backends: [{LoggerFileBackend, :info}, {LoggerFileBackend, :error}]

config :logger, :info,
  path: "./var/log/arp_server_info.log",
  level: :info,
  format: "\n$date $time [$level] $levelpad$metadata $message\n",
  metadata: [:module],
  rotate: %{max_bytes: 104_857_600, keep: 2}

config :logger, :error,
  path: "./var/log/arp_server_error.log",
  level: :error,
  format: "\n$date $time [$level] $levelpad$metadata $message\n",
  metadata: [:module],
  rotate: %{max_bytes: 104_857_600, keep: 2}
