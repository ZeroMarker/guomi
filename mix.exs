defmodule Guomi.MixProject do
  use Mix.Project

  def project do
    [
      app: :guomi,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "国密算法 Elixir 实现 - SM2, SM3, SM4",
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      description: "国密算法 (GM/T) Elixir 实现，支持 SM2、SM3、SM4 算法",
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/yourusername/guomi"
      },
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "Guomi",
      extras: ["README.md"],
      source_ref: "v#{project()[:version]}",
      source_url: "https://github.com/yourusername/guomi"
    ]
  end
end
