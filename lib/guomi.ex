defmodule Guomi do
  @moduledoc """
  Guomi algorithms facade.
  """

  @type algorithm :: :sm2 | :sm3 | :sm4

  @doc """
  Returns the algorithms exposed by this package.
  """
  @spec algorithms() :: [algorithm()]
  def algorithms, do: [:sm2, :sm3, :sm4]

  @doc """
  Returns runtime support for each algorithm.

  Support depends on the Erlang/OTP `:crypto` module and the OpenSSL version
  used to build the current runtime.
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
