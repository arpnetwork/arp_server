defmodule ARP.MixProject do
  use Mix.Project

  def project do
    [
      app: :arp_server,
      version: "0.1.0",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      description: """
      ARP Server
      """
    ]
  end

  def application do
    [
      extra_applications: [:logger, :os_mon, :ethereumex, :cowboy, :plug, :hackney],
      mod: {ARP.Application, []}
    ]
  end

  defp deps do
    [
      {:ranch, "~> 1.5"},
      {:poison, "~> 3.1"},
      {:cowboy, "~> 2.4"},
      {:plug, "~> 1.6"},
      {:jsonrpc2, git: "https://github.com/arpnetwork/jsonrpc2_ex.git"},
      {:hackney, "~> 1.13"},
      {:elixir_uuid, "~> 1.2"},
      {:libsecp256k1,
       github: "exthereum/libsecp256k1",
       ref: "e940555514061ece8f08cc773eecb1b5f5d9d0cf",
       manager: :rebar,
       override: true},
      {:ethereumex, "~> 0.3.2"},
      {:abi, "~> 0.1.8"},
      {:blockchain, "~> 0.1.7"},
      {:keccakf1600, "~> 2.0", hex: :keccakf1600_orig},
      {:pbkdf2, "~> 2.0"},
      {:erlscrypt, git: "git://github.com/K2InformaticsGmbH/erlscrypt.git"},
      {:ex_prompt, "~> 0.1.3"}
    ]
  end

  defp package do
    [
      maintainers: [
        "Wells Qiu",
        "Fludit9"
      ],
      licenses: ["Apache 2"],
      links: %{github: "https://github.com/arpnetwork/arp_server"},
      files: ~w(lib LICENSE mix.exs README.md)
    ]
  end
end
