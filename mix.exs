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
      extra_applications: [:logger, :cowboy, :plug],
      mod: {ARP.Application, []}
    ]
  end

  defp deps do
    [
      {:ranch, "~> 1.5"},
      {:poison, "~> 3.1"},
      {:cowboy, "~> 2.4"},
      {:plug, "~> 1.6"},
      {:elixir_uuid, "~> 1.2"}
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
