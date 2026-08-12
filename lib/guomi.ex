defmodule Guomi do
  @moduledoc """
  Guomi algorithms facade.

  ## Examples

      iex> Guomi.algorithms()
      [:sm2, :sm3, :sm4]

      iex> Guomi.supported()
      %{sm2: true, sm3: true, sm4: true}
  """

  @type algorithm :: :sm2 | :sm3 | :sm4

  @doc """
  Returns the algorithms exposed by this package.
  """
  @spec algorithms() :: [algorithm()]
  def algorithms, do: [:sm2, :sm3, :sm4]

  @doc """
  Returns runtime support for each algorithm.

  Since v0.5.0 all algorithms are implemented in pure Elixir and are
  always supported at runtime.
  """
  @spec supported() :: %{algorithm() => boolean()}
  def supported do
    %{
      sm2: Guomi.SM2.supported?(),
      sm3: Guomi.SM3.supported?(),
      sm4: Guomi.SM4.supported?()
    }
  end
end
