defmodule Guomi.SM2 do
  @moduledoc """
  Pure Elixir SM2 cryptographic operations (GM/T 0003-2012).

  SM2 is a Chinese commercial cryptographic algorithm standard for:
  - Key pair generation (ECDH)
  - Digital signature (ECDSA with SM3 pre-hash)
  - Encryption/decryption (ECDH + SM3 KDF + XOR + SM3 MAC)

  This is a pure Elixir implementation with no external dependencies.

  The encryption API uses a Guomi-specific compatibility format and repeats a
  32-byte XOR mask for longer messages. It must not be used to protect
  sensitive data or as part of a production protocol.
  """

  alias Guomi.SM2.Curve

  @type error_reason ::
          :invalid_key
          | :invalid_signature
          | :invalid_ciphertext
          | :decryption_failed

  @spec supported?() :: boolean()
  def supported?, do: true

  # -- Key generation ----------------------------------------------------------

  @spec generate_keypair :: {:ok, binary(), binary()}
  def generate_keypair do
    {priv, {_gx, _gy} = pub} = Curve.generate_keypair()
    priv_bin = <<priv::256-big>>
    pub_bin = Curve.encode_public(pub)
    {:ok, priv_bin, pub_bin}
  end

  # -- Signature ---------------------------------------------------------------

  @spec sign(binary() | iodata(), binary()) :: {:ok, binary()} | {:error, error_reason()}
  def sign(message, private_key) when is_binary(private_key) do
    with {:ok, priv_int} <- decode_private_key(private_key),
         {:ok, data} <- to_binary(message) do
      digest = Guomi.SM3.hash(data)
      Curve.sign(digest, priv_int)
    end
  end

  @spec verify(binary() | iodata(), binary(), binary()) ::
          {:ok, boolean()} | {:error, error_reason()}
  def verify(message, signature, public_key)
      when is_binary(signature) and is_binary(public_key) do
    with {:ok, pub_point} <- decode_public_key(public_key),
         :ok <- validate_signature(signature),
         {:ok, data} <- to_binary(message) do
      digest = Guomi.SM3.hash(data)
      {:ok, Curve.verify(digest, signature, pub_point)}
    end
  end

  # -- Encryption (ECDH + SM3 KDF + XOR + SM3 MAC) ----------------------------

  @spec encrypt(binary() | iodata(), binary()) :: {:ok, binary()} | {:error, error_reason()}
  def encrypt(plaintext, public_key) do
    with {:ok, data} <- to_binary(plaintext),
         {:ok, pub_point} <- decode_public_key(public_key),
         {ephemeral_priv, ephemeral_pub} <- Curve.generate_keypair(),
         {:ok, shared_x} <- Curve.shared_secret(ephemeral_priv, pub_point) do
      shared = <<shared_x::256-big>>
      {key_enc, key_mac} = derive_keys(shared)
      encrypted = xor_with_keystream(data, key_enc)
      mac = Guomi.SM3.hash(key_mac <> encrypted)
      {:ok, Curve.encode_public(ephemeral_pub) <> encrypted <> mac}
    end
  end

  @spec decrypt(binary(), binary()) :: {:ok, binary()} | {:error, error_reason()}
  def decrypt(ciphertext, _private_key) when byte_size(ciphertext) < 97 do
    {:error, :invalid_ciphertext}
  end

  def decrypt(ciphertext, private_key) do
    with {:ok, priv_int} <- decode_private_key(private_key),
         {:ok, ephemeral_pub_bin, encrypted_data, mac} <- split_ciphertext(ciphertext),
         {:ok, pub_point} <- decode_public_key(ephemeral_pub_bin),
         {:ok, shared_x} <- Curve.shared_secret(priv_int, pub_point) do
      shared = <<shared_x::256-big>>
      {key_enc, key_mac} = derive_keys(shared)
      expected_mac = Guomi.SM3.hash(key_mac <> encrypted_data)

      if secure_compare(mac, expected_mac) do
        {:ok, xor_with_keystream(encrypted_data, key_enc)}
      else
        {:error, :decryption_failed}
      end
    end
  end

  defp to_binary(data) do
    {:ok, IO.iodata_to_binary(data)}
  rescue
    ArgumentError -> {:error, :invalid_key}
  end

  # SM2 private keys must be in [1, n - 2] (GM/T 0003-2012).
  # A key of n - 1 would make (1 + d) ≡ 0 (mod n), so signing could never
  # produce a valid s and must be rejected instead of retrying forever.
  defp decode_private_key(<<key::256-big>>) do
    if key > 0 and key < Curve.n() - 1, do: {:ok, key}, else: {:error, :invalid_key}
  end

  defp decode_private_key(_), do: {:error, :invalid_key}

  defp decode_public_key(<<0x04, x_bin::binary-size(32), y_bin::binary-size(32)>>) do
    point = {:binary.decode_unsigned(x_bin, :big), :binary.decode_unsigned(y_bin, :big)}

    if valid_public_point?(point) do
      {:ok, point}
    else
      {:error, :invalid_key}
    end
  end

  defp decode_public_key(_), do: {:error, :invalid_key}

  defp valid_public_point?({x, y}) do
    x in 0..(Curve.p() - 1) and y in 0..(Curve.p() - 1) and
      mod(y * y, Curve.p()) ==
        mod(x * x * x + Curve.a() * x + Curve.b(), Curve.p())
  end

  defp validate_signature(<<r::256-big, s::256-big>>) do
    if r > 0 and r < Curve.n() and s > 0 and s < Curve.n(),
      do: :ok,
      else: {:error, :invalid_signature}
  end

  defp validate_signature(_), do: {:error, :invalid_signature}

  defp split_ciphertext(<<c1::binary-size(65), rest::binary>>) when byte_size(rest) >= 32 do
    c2_size = byte_size(rest) - 32
    <<c2::binary-size(c2_size), c3::binary-size(32)>> = rest
    {:ok, c1, c2, c3}
  end

  defp split_ciphertext(_), do: {:error, :invalid_ciphertext}

  defp mod(value, modulus) do
    value
    |> rem(modulus)
    |> Kernel.+(modulus)
    |> rem(modulus)
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
