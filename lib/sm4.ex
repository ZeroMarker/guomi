defmodule Guomi.SM4 do
  @moduledoc """
  SM4 block cipher helpers using Erlang `:crypto`.
  """

  @block_size 16
  @key_size 16

  @type error_reason ::
          :invalid_key_size
          | :invalid_iv_size
          | :invalid_block_size
          | :invalid_padding
          | :unsupported

  @spec supported?() :: boolean()
  def supported? do
    ciphers = :crypto.supports(:ciphers)
    :sm4_ecb in ciphers and :sm4_cbc in ciphers
  end

  @spec encrypt(binary(), binary(), keyword()) :: {:ok, binary()} | {:error, error_reason()}
  def encrypt(plaintext, key, opts \\ []) when is_binary(plaintext) and is_binary(key) do
    try do
      with :ok <- validate_key(key),
           {:ok, data} <- pad(plaintext, opts) do
        {:ok, :crypto.crypto_one_time(:sm4_ecb, key, <<>>, data, true)}
      else
        {:error, _} = err -> err
      end
    rescue
      _ -> {:error, :unsupported}
    end
  end

  @spec decrypt(binary(), binary(), keyword()) :: {:ok, binary()} | {:error, error_reason()}
  def decrypt(ciphertext, key, opts \\ []) when is_binary(ciphertext) and is_binary(key) do
    try do
      with :ok <- validate_key(key),
           :ok <- validate_block(ciphertext),
           plaintext <- :crypto.crypto_one_time(:sm4_ecb, key, <<>>, ciphertext, false),
           {:ok, out} <- unpad(plaintext, opts) do
        {:ok, out}
      else
        {:error, _} = err -> err
      end
    rescue
      _ -> {:error, :unsupported}
    end
  end

  @spec encrypt_cbc(binary(), binary(), binary(), keyword()) ::
          {:ok, binary()} | {:error, error_reason()}
  def encrypt_cbc(plaintext, key, iv, opts \\ [])
      when is_binary(plaintext) and is_binary(key) and is_binary(iv) do
    try do
      with :ok <- validate_key(key),
           :ok <- validate_iv(iv),
           {:ok, data} <- pad(plaintext, opts) do
        {:ok, :crypto.crypto_one_time(:sm4_cbc, key, iv, data, true)}
      else
        {:error, _} = err -> err
      end
    rescue
      _ -> {:error, :unsupported}
    end
  end

  @spec decrypt_cbc(binary(), binary(), binary(), keyword()) ::
          {:ok, binary()} | {:error, error_reason()}
  def decrypt_cbc(ciphertext, key, iv, opts \\ [])
      when is_binary(ciphertext) and is_binary(key) and is_binary(iv) do
    try do
      with :ok <- validate_key(key),
           :ok <- validate_iv(iv),
           :ok <- validate_block(ciphertext),
           plaintext <- :crypto.crypto_one_time(:sm4_cbc, key, iv, ciphertext, false),
           {:ok, out} <- unpad(plaintext, opts) do
        {:ok, out}
      else
        {:error, _} = err -> err
      end
    rescue
      _ -> {:error, :unsupported}
    end
  end

  defp validate_key(<<_::binary-size(@key_size)>>), do: :ok
  defp validate_key(_), do: {:error, :invalid_key_size}

  defp validate_iv(<<_::binary-size(@block_size)>>), do: :ok
  defp validate_iv(_), do: {:error, :invalid_iv_size}

  defp validate_block(data) when rem(byte_size(data), @block_size) == 0, do: :ok
  defp validate_block(_), do: {:error, :invalid_block_size}

  defp pad(data, opts) do
    case Keyword.get(opts, :padding, :pkcs7) do
      :none ->
        if rem(byte_size(data), @block_size) == 0 do
          {:ok, data}
        else
          {:error, :invalid_block_size}
        end

      :pkcs7 ->
        n = @block_size - rem(byte_size(data), @block_size)
        pad_len = if n == 0, do: @block_size, else: n
        {:ok, data <> :binary.copy(<<pad_len>>, pad_len)}

      _ ->
        {:error, :invalid_padding}
    end
  end

  defp unpad(data, opts) do
    case Keyword.get(opts, :padding, :pkcs7) do
      :none ->
        {:ok, data}

      :pkcs7 ->
        size = byte_size(data)

        if size == 0 do
          {:error, :invalid_padding}
        else
          pad_len = :binary.last(data)

          cond do
            pad_len < 1 or pad_len > @block_size ->
              {:error, :invalid_padding}

            pad_len > size ->
              {:error, :invalid_padding}

            true ->
              <<plain::binary-size(size - pad_len), pad::binary-size(pad_len)>> = data

              if pad == :binary.copy(<<pad_len>>, pad_len) do
                {:ok, plain}
              else
                {:error, :invalid_padding}
              end
          end
        end

      _ ->
        {:error, :invalid_padding}
    end
  end
end
