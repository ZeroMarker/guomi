defmodule Guomi.SM2 do
  @moduledoc """
  Pure Elixir SM2 cryptographic operations (GM/T 0003-2012).

  SM2 is a Chinese commercial cryptographic algorithm standard for:
  - Key pair generation (ECDH)
  - Digital signature (ECDSA with SM3 pre-hash)
  - Encryption/decryption (ECDH + SM3 KDF + XOR + SM3 MAC)

  This is a pure Elixir implementation with no external dependencies.

  The explicit `sign_standard/3`, `verify_standard/4`, `encrypt_standard/2`, and
  `decrypt_standard/2` APIs implement ZA-aware signatures and the standard SM3
  KDF. The shorter legacy APIs retain the historical Guomi-specific format;
  legacy encryption repeats a 32-byte XOR mask and must not protect sensitive
  data or be used as part of a production protocol.
  """

  alias Guomi.SM2.Curve

  @max_user_id_bytes 8191

  @type error_reason ::
          :invalid_key
          | :invalid_input
          | :invalid_signature
          | :invalid_ciphertext
          | :decryption_failed

  @spec supported?() :: boolean()
  @doc "Returns `true`; the current SM2 primitives are implemented entirely in Elixir."
  def supported?, do: true

  # -- Key generation ----------------------------------------------------------

  @spec generate_keypair :: {:ok, binary(), binary()}
  @doc """
  Generates an SM2 key pair.

  The private key is a 32-byte big-endian integer. The public key is a 65-byte
  uncompressed point encoded as `0x04 || x || y`.
  """
  def generate_keypair do
    {priv, {_gx, _gy} = pub} = Curve.generate_keypair()
    priv_bin = <<priv::256-big>>
    pub_bin = Curve.encode_public(pub)
    {:ok, priv_bin, pub_bin}
  end

  # -- Signature ---------------------------------------------------------------

  @spec sign(binary() | iodata(), binary()) :: {:ok, binary()} | {:error, error_reason()}
  @doc """
  Signs `message` with a 32-byte private key and returns raw `r || s` bytes.

  This compatibility API signs `SM3(message)` and does not calculate the SM2
  user identity digest ZA. Do not assume interoperability with standard SM2
  signing APIs. Invalid iodata returns `{:error, :invalid_input}`.
  """
  def sign(message, private_key) when is_binary(private_key) do
    with {:ok, priv_int} <- decode_signing_private_key(private_key),
         {:ok, data} <- to_binary(message) do
      digest = Guomi.SM3.hash(data)
      Curve.sign(digest, priv_int)
    end
  end

  @spec verify(binary() | iodata(), binary(), binary()) ::
          {:ok, boolean()} | {:error, error_reason()}
  @doc """
  Verifies a raw 64-byte `r || s` compatibility signature.

  Returns `{:ok, false}` for a well-formed but invalid signature and an error for
  malformed keys, signatures, or message input. This API does not calculate ZA.
  """
  def verify(message, signature, public_key)
      when is_binary(signature) and is_binary(public_key) do
    with {:ok, pub_point} <- decode_public_key(public_key),
         :ok <- validate_signature(signature),
         {:ok, data} <- to_binary(message) do
      digest = Guomi.SM3.hash(data)
      {:ok, Curve.verify(digest, signature, pub_point)}
    end
  end

  @doc """
  Calculates the SM2 user identity digest ZA for `user_id` and `public_key`.

  The user ID must be a binary no longer than 8191 bytes so its bit length fits
  the standard 16-bit `ENTLA` field.
  """
  @spec user_identity_digest(binary(), binary()) ::
          {:ok, binary()} | {:error, error_reason()}
  def user_identity_digest(user_id, public_key)
      when is_binary(user_id) and is_binary(public_key) do
    with :ok <- validate_user_id(user_id),
         {:ok, public_point} <- decode_public_key(public_key) do
      {:ok, identity_digest(user_id, public_point)}
    end
  end

  def user_identity_digest(_user_id, _public_key), do: {:error, :invalid_input}

  @doc """
  Produces a standards-compatible raw SM2 signature using an explicit user ID.

  The signed digest is `SM3(ZA || message)`. The result is 64-byte raw
  `r || s`; DER encoding is intentionally not implicit.
  """
  @spec sign_standard(binary() | iodata(), binary(), binary()) ::
          {:ok, binary()} | {:error, error_reason()}
  def sign_standard(message, private_key, user_id)
      when is_binary(private_key) and is_binary(user_id) do
    with {:ok, private_int} <- decode_signing_private_key(private_key),
         :ok <- validate_user_id(user_id),
         {:ok, data} <- to_binary(message) do
      public_point = Curve.mul(Curve.generator(), private_int)
      digest = Guomi.SM3.hash(identity_digest(user_id, public_point) <> data)
      Curve.sign(digest, private_int)
    end
  end

  def sign_standard(_message, _private_key, _user_id), do: {:error, :invalid_input}

  @doc """
  Verifies a standards-compatible raw SM2 signature using the same user ID.

  Returns `{:ok, false}` when the inputs are well formed but the signature or
  user ID does not match.
  """
  @spec verify_standard(binary() | iodata(), binary(), binary(), binary()) ::
          {:ok, boolean()} | {:error, error_reason()}
  def verify_standard(message, signature, public_key, user_id)
      when is_binary(signature) and is_binary(public_key) and is_binary(user_id) do
    with :ok <- validate_user_id(user_id),
         {:ok, public_point} <- decode_public_key(public_key),
         :ok <- validate_signature(signature),
         {:ok, data} <- to_binary(message) do
      digest = Guomi.SM3.hash(identity_digest(user_id, public_point) <> data)
      {:ok, Curve.verify(digest, signature, public_point)}
    end
  end

  def verify_standard(_message, _signature, _public_key, _user_id),
    do: {:error, :invalid_input}

  # -- Encryption (ECDH + SM3 KDF + XOR + SM3 MAC) ----------------------------

  @spec encrypt(binary() | iodata(), binary()) :: {:ok, binary()} | {:error, error_reason()}
  @doc """
  Encrypts with the legacy Guomi-specific `C1 || C2 || C3` compatibility format.

  This format repeats a 32-byte XOR mask for longer messages and must not be used
  for sensitive data or production protocols. Invalid iodata returns
  `{:error, :invalid_input}`.
  """
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
  @doc """
  Decrypts the legacy Guomi-specific compatibility ciphertext format.

  Returns `:invalid_ciphertext` for malformed framing, `:invalid_key` for an
  invalid private key, or `:decryption_failed` when authentication fails.
  """
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

  @doc """
  Encrypts a non-empty message using the standard SM2 KDF and `C1 || C3 || C2`.

  C1 is a 65-byte uncompressed point, C3 is the 32-byte SM3 integrity digest,
  and C2 has the same length as the plaintext. This API has not undergone an
  independent security audit.
  """
  @spec encrypt_standard(binary() | iodata(), binary()) ::
          {:ok, binary()} | {:error, error_reason()}
  def encrypt_standard(plaintext, public_key) when is_binary(public_key) do
    with {:ok, data} <- to_binary(plaintext),
         :ok <- validate_nonempty(data),
         {:ok, public_point} <- decode_public_key(public_key) do
      do_encrypt_standard(data, public_point)
    end
  end

  def encrypt_standard(_plaintext, _public_key), do: {:error, :invalid_input}

  @doc """
  Decrypts standard raw SM2 `C1 || C3 || C2` ciphertext.

  This function never falls back to the legacy Guomi format. Integrity failure,
  an invalid ephemeral point, or an all-zero KDF returns `:decryption_failed`.
  """
  @spec decrypt_standard(binary(), binary()) ::
          {:ok, binary()} | {:error, error_reason()}
  def decrypt_standard(ciphertext, private_key)
      when is_binary(ciphertext) and is_binary(private_key) do
    with {:ok, private_int} <- decode_private_key(private_key),
         {:ok, c1, c3, c2} <- split_standard_ciphertext(ciphertext),
         {:ok, ephemeral_point} <- decode_ciphertext_point(c1),
         {:ok, {x2, y2}} <- Curve.shared_point(private_int, ephemeral_point),
         {:ok, mask} <- sm2_kdf(<<x2::256-big, y2::256-big>>, byte_size(c2)),
         false <- zero_binary?(mask),
         plaintext <- :crypto.exor(c2, mask),
         expected_c3 <- Guomi.SM3.hash(<<x2::256-big>> <> plaintext <> <<y2::256-big>>),
         true <- secure_compare(c3, expected_c3) do
      {:ok, plaintext}
    else
      {:error, :invalid_key} = error -> error
      {:error, :invalid_ciphertext} = error -> error
      _ -> {:error, :decryption_failed}
    end
  end

  def decrypt_standard(_ciphertext, _private_key), do: {:error, :invalid_input}

  defp to_binary(data) do
    {:ok, IO.iodata_to_binary(data)}
  rescue
    ArgumentError -> {:error, :invalid_input}
  end

  defp validate_user_id(user_id) when byte_size(user_id) <= @max_user_id_bytes, do: :ok
  defp validate_user_id(_user_id), do: {:error, :invalid_input}

  defp validate_nonempty(<<>>), do: {:error, :invalid_input}
  defp validate_nonempty(_data), do: :ok

  defp identity_digest(user_id, {public_x, public_y}) do
    {generator_x, generator_y} = Curve.generator()
    entl = byte_size(user_id) * 8
    curve_a = Curve.a()
    curve_b = Curve.b()

    Guomi.SM3.hash(
      <<entl::16-big>> <>
        user_id <>
        <<curve_a::256-big, curve_b::256-big, generator_x::256-big,
          generator_y::256-big, public_x::256-big, public_y::256-big>>
    )
  end

  defp do_encrypt_standard(data, public_point) do
    {ephemeral_private, ephemeral_public} = Curve.generate_keypair()

    with {:ok, {x2, y2}} <- Curve.shared_point(ephemeral_private, public_point),
         {:ok, mask} <- sm2_kdf(<<x2::256-big, y2::256-big>>, byte_size(data)) do
      if zero_binary?(mask) do
        do_encrypt_standard(data, public_point)
      else
        c1 = Curve.encode_public(ephemeral_public)
        c2 = :crypto.exor(data, mask)
        c3 = Guomi.SM3.hash(<<x2::256-big>> <> data <> <<y2::256-big>>)
        {:ok, c1 <> c3 <> c2}
      end
    end
  end

  defp sm2_kdf(_z, 0), do: {:error, :invalid_input}

  defp sm2_kdf(z, length) do
    blocks = div(length + 31, 32)

    if blocks > 0xFFFFFFFF do
      {:error, :invalid_input}
    else
      material =
        for counter <- 1..blocks, into: <<>> do
          Guomi.SM3.hash(z <> <<counter::32-big>>)
        end

      {:ok, :binary.part(material, 0, length)}
    end
  end

  defp zero_binary?(data), do: do_zero_binary?(data)
  defp do_zero_binary?(<<>>), do: true
  defp do_zero_binary?(<<0, rest::binary>>), do: do_zero_binary?(rest)
  defp do_zero_binary?(_data), do: false

  defp split_standard_ciphertext(
         <<c1::binary-size(65), c3::binary-size(32), c2::binary>>
       )
       when byte_size(c2) > 0,
       do: {:ok, c1, c3, c2}

  defp split_standard_ciphertext(_ciphertext), do: {:error, :invalid_ciphertext}

  defp decode_ciphertext_point(c1) do
    case decode_public_key(c1) do
      {:ok, point} -> {:ok, point}
      {:error, :invalid_key} -> {:error, :decryption_failed}
    end
  end

  defp decode_private_key(<<key::256-big>>) do
    if key > 0 and key < Curve.n(), do: {:ok, key}, else: {:error, :invalid_key}
  end

  defp decode_private_key(_), do: {:error, :invalid_key}

  # Signing additionally excludes n - 1 because (1 + d) has no inverse mod n.
  defp decode_signing_private_key(private_key) do
    case decode_private_key(private_key) do
      {:ok, key} when key < Curve.n() - 1 -> {:ok, key}
      _ -> {:error, :invalid_key}
    end
  end

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
