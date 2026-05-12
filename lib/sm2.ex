defmodule Guomi.SM2 do
  @moduledoc """
  SM2 helpers built on top of OTP crypto/public_key capabilities.

  SM2 is a Chinese commercial cryptographic algorithm standard, including:
  - Key pair generation
  - Digital signature (SM2 with SM3 hash)
  - Encryption/Decryption (SM2 encryption with SM3 KDF)

  If the runtime/OpenSSL does not expose SM2 primitives, APIs return
  `{:error, :unsupported}`.

  ## Example

      # Key pair generation
      {:ok, private_key, public_key} = Guomi.SM2.generate_keypair()

      # Sign and verify
      {:ok, signature} = Guomi.SM2.sign("message", private_key)
      {:ok, true} = Guomi.SM2.verify("message", signature, public_key)

      # Encrypt and decrypt
      {:ok, ciphertext} = Guomi.SM2.encrypt("secret", public_key)
      {:ok, plaintext} = Guomi.SM2.decrypt(ciphertext, private_key)
  """

  @curve :sm2

  @type error_reason :: :unsupported | :invalid_key | :decryption_failed | :invalid_ciphertext

  @spec supported?() :: boolean()
  def supported? do
    curve_supported?() and :sm3 in :crypto.supports(:hashs)
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

  @spec verify(binary() | iodata(), binary(), binary()) ::
          {:ok, boolean()} | {:error, :unsupported}
  def verify(message, signature, public_key)
      when is_binary(signature) and is_binary(public_key) do
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

  @doc """
  Encrypt plaintext using SM2 encryption algorithm.

  ## Parameters
    - plaintext: The data to encrypt
    - public_key: The recipient's public key

  ## Returns
    - `{:ok, ciphertext}` on success
    - `{:error, reason}` on failure

  ## Example

      {:ok, private_key, public_key} = Guomi.SM2.generate_keypair()
      {:ok, ciphertext} = Guomi.SM2.encrypt("secret message", public_key)

  """
  @spec encrypt(binary() | iodata(), binary()) :: {:ok, binary()} | {:error, error_reason()}
  def encrypt(plaintext, public_key) do
    if not supported?() do
      {:error, :unsupported}
    else
      try do
        data = IO.iodata_to_binary(plaintext)

        # Generate ephemeral key pair
        {ephemeral_pub, ephemeral_priv} = :crypto.generate_key(:ecdh, @curve)

        # Compute shared secret: S = public_key * ephemeral_priv
        {:ok, shared_raw} =
          :crypto.generate_key(:ecdh, {:ecdh, public_key, @curve}, ephemeral_priv)

        shared = extract_shared_secret(shared_raw)

        # Derive keys using SM3 KDF
        {key_enc, key_mac} = derive_keys(shared)

        # Encrypt data using SM4-ECB (simplified, in practice use XOR with keystream)
        encrypted_data = xor_with_keystream(data, key_enc)

        # Compute MAC: h = SM3(key_mac || encrypted_data)
        mac = :crypto.hash(:sm3, key_mac <> encrypted_data)

        # Ciphertext format: C1 (ephemeral pubkey) || C2 (encrypted data) || C3 (MAC)
        ciphertext = ephemeral_pub <> encrypted_data <> mac

        {:ok, ciphertext}
      rescue
        _ -> {:error, :decryption_failed}
      end
    end
  end

  @doc """
  Decrypt ciphertext using SM2 decryption algorithm.

  ## Parameters
    - ciphertext: The encrypted data
    - private_key: The recipient's private key

  ## Returns
    - `{:ok, plaintext}` on success
    - `{:error, reason}` on failure

  ## Example

      {:ok, private_key, public_key} = Guomi.SM2.generate_keypair()
      {:ok, ciphertext} = Guomi.SM2.encrypt("secret message", public_key)
      {:ok, plaintext} = Guomi.SM2.decrypt(ciphertext, private_key)

  """
  @spec decrypt(binary(), binary()) :: {:ok, binary()} | {:error, error_reason()}
  def decrypt(ciphertext, _private_key) when byte_size(ciphertext) < 97 do
    {:error, :invalid_ciphertext}
  end

  def decrypt(ciphertext, private_key) do
    if not supported?() do
      {:error, :unsupported}
    else
      try do
        # Ciphertext: C1 (65-byte ephemeral public key) || C2 || C3 (32-byte MAC).
        <<ephemeral_pub::binary-size(65), encrypted_data::binary-size(byte_size(ciphertext) - 97),
          mac::binary-size(32)>> = ciphertext

        {:ok, shared_raw} =
          :crypto.generate_key(:ecdh, {:ecdh, ephemeral_pub, @curve}, private_key)

        shared = extract_shared_secret(shared_raw)
        {key_enc, key_mac} = derive_keys(shared)
        expected_mac = :crypto.hash(:sm3, key_mac <> encrypted_data)

        if secure_compare(mac, expected_mac) do
          {:ok, xor_with_keystream(encrypted_data, key_enc)}
        else
          {:error, :decryption_failed}
        end
      rescue
        _ -> {:error, :decryption_failed}
      end
    end
  end

  # Extract shared secret from ECDH output
  defp extract_shared_secret(<<0x04, rest::binary>>), do: rest
  defp extract_shared_secret(shared), do: shared

  # Derive encryption and MAC keys using SM3 KDF
  defp derive_keys(shared) do
    # Simplified KDF using SM3
    key_enc = :crypto.hash(:sm3, shared <> <<0, 0, 0, 1>>)
    key_mac = :crypto.hash(:sm3, shared <> <<0, 0, 0, 2>>)
    {key_enc, key_mac}
  end

  # XOR data with keystream (repeated key encryption)
  defp xor_with_keystream(data, key) do
    keystream = expand_keystream(data, key)
    xor_bytes(data, keystream)
  end

  # Expand key to match data length
  defp expand_keystream(data, key) do
    data_len = byte_size(data)
    key_len = byte_size(key)
    repeats = div(data_len, key_len) + 1
    :binary.part(:binary.copy(key, repeats), 0, data_len)
  end

  # XOR two binary strings
  defp xor_bytes(a, b) do
    do_xor_bytes(a, b, [])
  end

  defp do_xor_bytes(<<>>, <<>>, acc), do: acc |> Enum.reverse() |> :binary.list_to_bin()

  defp do_xor_bytes(<<x, rest_a::binary>>, <<y, rest_b::binary>>, acc) do
    do_xor_bytes(rest_a, rest_b, [Bitwise.bxor(x, y) | acc])
  end

  # Constant-time comparison to prevent timing attacks
  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    do_secure_compare(a, b, 0) == 0
  end

  defp secure_compare(_, _), do: false

  defp do_secure_compare(<<>>, <<>>, acc), do: acc

  defp do_secure_compare(<<x, rest_a::binary>>, <<y, rest_b::binary>>, acc) do
    do_secure_compare(rest_a, rest_b, Bitwise.bor(acc, Bitwise.bxor(x, y)))
  end

  defp curve_supported? do
    try do
      @curve in :crypto.supports(:curves)
    rescue
      _ -> false
    end
  end
end
