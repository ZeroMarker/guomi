defmodule Guomi.MixProject do
  use Mix.Project

  @version "0.5.1"

  def project do
    [
      app: :guomi,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      test_coverage: [tool: ExCoveralls],
      deps: deps(),
      description: "Guomi cryptographic algorithms for Elixir (SM2/SM3/SM4)",
      package: package(),
      source_url: "https://github.com/ZeroMarker/guomi",
      docs: docs(),
      dialyzer: [plt_add_apps: [:mix]],
      escript: [main_module: Guomi.CLI]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :public_key]
    ]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/ZeroMarker/guomi"},
      files:
        ~w(lib bench .formatter.exs mix.exs README.md cli.md sm2_migration.md future_work.md
           SECURITY.md CHANGELOG.md todo.md hex.pm.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md",
        "cli.md",
        "sm2_migration.md",
        "future_work.md",
        "SECURITY.md",
        "CHANGELOG.md",
        "todo.md",
        "hex.pm.md",
        "LICENSE"
      ],
      source_ref: "v#{@version}"
    ]
  end
end
