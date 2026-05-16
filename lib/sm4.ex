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
  rescue
    _ -> false
  end

  @spec encrypt(binary(), binary(), keyword()) :: {:ok, binary()} | {:error, error_reason()}
  def encrypt(plaintext, key, opts \\ []) when is_binary(plaintext) and is_binary(key) do
    with :ok <- validate_key(key),
         {:ok, data} <- pad(plaintext, opts) do
      crypto_one_time(:sm4_ecb, key, <<>>, data, true)
    else
      {:error, _} = err -> err
    end
  end

  @spec decrypt(binary(), binary(), keyword()) :: {:ok, binary()} | {:error, error_reason()}
  def decrypt(ciphertext, key, opts \\ []) when is_binary(ciphertext) and is_binary(key) do
    with :ok <- validate_key(key),
         :ok <- validate_block(ciphertext),
         {:ok, plaintext} <- crypto_one_time(:sm4_ecb, key, <<>>, ciphertext, false),
         {:ok, out} <- unpad(plaintext, opts) do
      {:ok, out}
    else
      {:error, _} = err -> err
    end
  end

  @spec encrypt_cbc(binary(), binary(), binary(), keyword()) ::
          {:ok, binary()} | {:error, error_reason()}
  def encrypt_cbc(plaintext, key, iv, opts \\ [])
      when is_binary(plaintext) and is_binary(key) and is_binary(iv) do
    with :ok <- validate_key(key),
         :ok <- validate_iv(iv),
         {:ok, data} <- pad(plaintext, opts) do
      crypto_one_time(:sm4_cbc, key, iv, data, true)
    else
      {:error, _} = err -> err
    end
  end

  @spec decrypt_cbc(binary(), binary(), binary(), keyword()) ::
          {:ok, binary()} | {:error, error_reason()}
  def decrypt_cbc(ciphertext, key, iv, opts \\ [])
      when is_binary(ciphertext) and is_binary(key) and is_binary(iv) do
    with :ok <- validate_key(key),
         :ok <- validate_iv(iv),
         :ok <- validate_block(ciphertext),
         {:ok, plaintext} <- crypto_one_time(:sm4_cbc, key, iv, ciphertext, false),
         {:ok, out} <- unpad(plaintext, opts) do
      {:ok, out}
    else
      {:error, _} = err -> err
    end
  end

  defp validate_key(<<_::binary-size(@key_size)>>), do: :ok
  defp validate_key(_), do: {:error, :invalid_key_size}

  defp validate_iv(<<_::binary-size(@block_size)>>), do: :ok
  defp validate_iv(_), do: {:error, :invalid_iv_size}

  defp validate_block(data) when rem(byte_size(data), @block_size) == 0, do: :ok
  defp validate_block(_), do: {:error, :invalid_block_size}

  defp crypto_one_time(cipher, key, iv, data, encrypt?) do
    {:ok, :crypto.crypto_one_time(cipher, key, iv, data, encrypt?)}
  rescue
    ErlangError -> {:error, :unsupported}
  end

  defp pad(data, opts) do
    case Keyword.get(opts, :padding, :pkcs7) do
      :none ->
        if rem(byte_size(data), @block_size) == 0 do
          {:ok, data}
        else
          {:error, :invalid_block_size}
        end

      :pkcs7 ->
        pad_len = pkcs7_pad_length(data)
        {:ok, data <> :binary.copy(<<pad_len>>, pad_len)}

      _ ->
        {:error, :invalid_padding}
    end
  end

  defp pkcs7_pad_length(data) do
    case rem(byte_size(data), @block_size) do
      0 -> @block_size
      used -> @block_size - used
    end
  end

  defp unpad(data, opts) do
    case Keyword.get(opts, :padding, :pkcs7) do
      :none ->
        {:ok, data}

      :pkcs7 ->
        unpad_pkcs7(data)

      _ ->
        {:error, :invalid_padding}
    end
  end

  defp unpad_pkcs7(<<>>), do: {:error, :invalid_padding}

  defp unpad_pkcs7(data) do
    data
    |> :binary.last()
    |> validate_pkcs7_padding_length(byte_size(data))
    |> remove_pkcs7_padding(data)
  end

  defp validate_pkcs7_padding_length(pad_len, size)
       when pad_len in 1..@block_size and pad_len <= size do
    {:ok, pad_len}
  end

  defp validate_pkcs7_padding_length(_pad_len, _size), do: {:error, :invalid_padding}

  defp remove_pkcs7_padding({:error, _} = err, _data), do: err

  defp remove_pkcs7_padding({:ok, pad_len}, data) do
    if valid_pkcs7_padding?(data, pad_len) do
      size = byte_size(data)
      <<plain::binary-size(size - pad_len), _pad::binary-size(pad_len)>> = data
      {:ok, plain}
    else
      {:error, :invalid_padding}
    end
  end

  defp valid_pkcs7_padding?(data, pad_len) do
    size = byte_size(data)
    <<block::binary-size(@block_size)>> = :binary.part(data, size - @block_size, @block_size)
    padding_start = @block_size - pad_len

    validate_pkcs7_block(block, pad_len, padding_start, 0, 0) == 0
  end

  defp validate_pkcs7_block(<<>>, _pad_len, _padding_start, _index, acc), do: acc

  defp validate_pkcs7_block(<<byte, rest::binary>>, pad_len, padding_start, index, acc) do
    diff =
      if index >= padding_start do
        Bitwise.bxor(byte, pad_len)
      else
        0
      end

    validate_pkcs7_block(rest, pad_len, padding_start, index + 1, Bitwise.bor(acc, diff))
  end
end
