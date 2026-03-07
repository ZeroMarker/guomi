defmodule Guomi.SM3 do
  @moduledoc """
  SM3 hash helpers based on `:crypto`.
  """

  @type input :: binary() | iodata()

  @spec supported?() :: boolean()
  def supported? do
    :sm3 in :crypto.supports(:hashs)
  end

  @spec hash(input()) :: binary()
  def hash(data) do
    :crypto.hash(:sm3, IO.iodata_to_binary(data))
  end

  @spec hash_hex(input()) :: String.t()
  def hash_hex(data) do
    data
    |> hash()
    |> Base.encode16(case: :lower)
  end
end
