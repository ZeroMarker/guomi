defmodule Guomi.MixProject do
  use Mix.Project

  @version "0.3.0-dev"

  def project do
    [
      app: :guomi,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
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
      {:credo, "~> 1.7", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/ZeroMarker/guomi"},
      files: ~w(lib .formatter.exs mix.exs README.md CHANGELOG.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "LICENSE", "CHANGELOG.md"],
      source_ref: "v#{@version}"
    ]
  end
end
