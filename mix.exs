defmodule Guomi.MixProject do
  use Mix.Project

  def project do
    [
      app: :guomi,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Guomi cryptographic algorithms for Elixir (SM2/SM3/SM4)",
      package: package(),
      source_url: "https://example.com/guomi"
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :public_key]
    ]
  end

  defp deps do
    []
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://example.com/guomi"}
    ]
  end
end
