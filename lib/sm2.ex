defmodule Guomi.SM2 do
  @moduledoc """
  Pure Elixir SM2 cryptographic operations (GM/T 0003-2012).

  SM2 is a Chinese commercial cryptographic algorithm standard for:
  - Key pair generation (ECDH)
  - Digital signature (ECDSA with SM3 pre-hash)
  - Encryption/decryption (ECDH + SM3 KDF + XOR + SM3 MAC)

  This is a pure Elixir implementation with no external dependencies.
  """

  alias Guomi.SM2.Curve

  @type error_reason :: :unsupported | :invalid_key | :decryption_failed | :invalid_ciphertext

  @spec supported?() :: boolean()
  def supported?, do: true

  # -- Key generation ----------------------------------------------------------

  @spec generate_keypair :: {:ok, binary(), binary()} | {:error, :unsupported}
  def generate_keypair do
    {priv, {_gx, _gy} = pub} = Curve.generate_keypair()
    priv_bin = <<priv::32-big>>
    pub_bin = Curve.encode_public(pub)
    {:ok, priv_bin, pub_bin}
  rescue
    _ -> {:error, :unsupported}
  end

  # -- Signature ---------------------------------------------------------------

  @spec sign(binary() | iodata(), binary()) :: {:ok, binary()} | {:error, error_reason()}
  def sign(message, private_key) when is_binary(private_key) do
    data = IO.iodata_to_binary(message)
    digest = Guomi.SM3.hash(data)
    priv_int = Curve.private_key_to_int(private_key)

    Curve.sign(digest, priv_int)
  rescue
    _ -> {:error, :unsupported}
  end

  @spec verify(binary() | iodata(), binary(), binary()) ::
          {:ok, boolean()} | {:error, error_reason()}
  def verify(message, signature, public_key)
      when is_binary(signature) and is_binary(public_key) do
    data = IO.iodata_to_binary(message)
    digest = Guomi.SM3.hash(data)
    pub_point = Curve.decode_public(public_key)

    {:ok, Curve.verify(digest, signature, pub_point)}
  rescue
    _ -> {:error, :unsupported}
  end

  # -- Encryption (ECDH + SM3 KDF + XOR + SM3 MAC) ----------------------------

  @spec encrypt(binary() | iodata(), binary()) :: {:ok, binary()} | {:error, error_reason()}
  def encrypt(plaintext, public_key) do
    data = IO.iodata_to_binary(plaintext)
    pub_point = Curve.decode_public(public_key)

    # Generate ephemeral key pair
    {ephemeral_priv, ephemeral_pub} = Curve.generate_keypair()

    # Compute shared secret
    {:ok, shared_x} = Curve.shared_secret(ephemeral_priv, pub_point)

    # Derive encryption and MAC keys using SM3 KDF
    shared = <<shared_x::32-big>>
    {key_enc, key_mac} = derive_keys(shared)

    # Encrypt data using XOR with keystream
    encrypted = xor_with_keystream(data, key_enc)

    # Compute MAC: SM3(key_mac || encrypted_data)
    mac = Guomi.SM3.hash(key_mac <> encrypted)

    # Ciphertext: C1 (ephemeral pubkey) || C2 (encrypted data) || C3 (MAC)
    ephemeral_pub_bin = Curve.encode_public(ephemeral_pub)
    ciphertext = ephemeral_pub_bin <> encrypted <> mac

    {:ok, ciphertext}
  rescue
    _ -> {:error, :decryption_failed}
  end

  @spec decrypt(binary(), binary()) :: {:ok, binary()} | {:error, error_reason()}
  def decrypt(ciphertext, _private_key) when byte_size(ciphertext) < 97 do
    {:error, :invalid_ciphertext}
  end

  def decrypt(ciphertext, private_key) do
    # Ciphertext: C1 (65-byte ephemeral public key) || C2 || C3 (32-byte MAC)
    <<ephemeral_pub_bin::binary-size(65), encrypted_data::binary-size(byte_size(ciphertext) - 97),
      mac::binary-size(32)>> =
      ciphertext

    pub_point = Curve.decode_public(ephemeral_pub_bin)
    priv_int = Curve.private_key_to_int(private_key)

    {:ok, shared_x} = Curve.shared_secret(priv_int, pub_point)
    shared = <<shared_x::32-big>>

    {key_enc, key_mac} = derive_keys(shared)
    expected_mac = Guomi.SM3.hash(key_mac <> encrypted_data)

    if secure_compare(mac, expected_mac) do
      {:ok, xor_with_keystream(encrypted_data, key_enc)}
    else
      {:error, :decryption_failed}
    end
  rescue
    _ -> {:error, :decryption_failed}
  end

  # -- KDF: Derive encryption and MAC keys from shared secret -----------------

  defp derive_keys(shared) do
    # Simplified KDF using SM3 with different counter values
    key_enc = Guomi.SM3.hash(shared <> <<0, 0, 0, 1>>)
    key_mac = Guomi.SM3.hash(shared <> <<0, 0, 0, 2>>)
    {key_enc, key_mac}
  end

  # -- XOR with keystream -----------------------------------------------------

  defp xor_with_keystream(data, key) do
    key_len = byte_size(key)
    data_len = byte_size(data)
    repeats = div(data_len, key_len) + 1
    keystream = :binary.part(:binary.copy(key, repeats), 0, data_len)
    :crypto.exor(data, keystream)
  end

  # -- Constant-time comparison -----------------------------------------------

  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    do_secure_compare(a, b, 0) == 0
  end

  defp secure_compare(_, _), do: false

  defp do_secure_compare(<<>>, <<>>, acc), do: acc

  defp do_secure_compare(<<x, rest_a::binary>>, <<y, rest_b::binary>>, acc) do
    do_secure_compare(rest_a, rest_b, Bitwise.bor(acc, Bitwise.bxor(x, y)))
  end
end
