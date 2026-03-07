defmodule Guomi.SM2 do
  @moduledoc """
  SM2 helpers built on top of OTP crypto/public_key capabilities.

  If the runtime/OpenSSL does not expose SM2 primitives, APIs return
  `{:error, :unsupported}`.
  """

  @curve :sm2

  @spec supported?() :: boolean()
  def supported? do
    curve_supported?() and (:sm3 in :crypto.supports(:hashs))
  end

  @spec generate_keypair() :: {:ok, binary(), binary()} | {:error, :unsupported}
  def generate_keypair do
    if supported?() do
      try do
        {public_key, private_key} = :crypto.generate_key(:ecdh, @curve)
        {:ok, private_key, public_key}
      rescue
        _ -> {:error, :unsupported}
      end
    else
      {:error, :unsupported}
    end
  end

  @spec sign(binary() | iodata(), binary()) :: {:ok, binary()} | {:error, :unsupported}
  def sign(message, private_key) when is_binary(private_key) do
    if supported?() do
      data = IO.iodata_to_binary(message)
      digest = :crypto.hash(:sm3, data)

      try do
        {:ok, :crypto.sign(:ecdsa, :none, digest, [private_key, @curve])}
      rescue
        _ ->
          try do
            {:ok, :crypto.sign(:ecdsa, :sm3, data, [private_key, @curve])}
          rescue
            _ -> {:error, :unsupported}
          end
      end
    else
      {:error, :unsupported}
    end
  end

  @spec verify(binary() | iodata(), binary(), binary()) :: {:ok, boolean()} | {:error, :unsupported}
  def verify(message, signature, public_key) when is_binary(signature) and is_binary(public_key) do
    if supported?() do
      data = IO.iodata_to_binary(message)
      digest = :crypto.hash(:sm3, data)

      try do
        {:ok, :crypto.verify(:ecdsa, :none, digest, signature, [public_key, @curve])}
      rescue
        _ ->
          try do
            {:ok, :crypto.verify(:ecdsa, :sm3, data, signature, [public_key, @curve])}
          rescue
            _ -> {:error, :unsupported}
          end
      end
    else
      {:error, :unsupported}
    end
  end

  @spec encrypt(binary(), binary()) :: {:ok, binary()} | {:error, :unsupported}
  def encrypt(_plaintext, _public_key), do: {:error, :unsupported}

  @spec decrypt(binary(), binary()) :: {:ok, binary()} | {:error, :unsupported}
  def decrypt(_ciphertext, _private_key), do: {:error, :unsupported}

  defp curve_supported? do
    try do
      @curve in :crypto.supports(:curves)
    rescue
      _ -> false
    end
  end
end
