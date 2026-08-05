defmodule Guomi.SM4 do
  import Bitwise

  @moduledoc """
  Pure Elixir SM4 block cipher (GM/T 0002-2012).
  """

  @block_size 16
  @key_size 16

  @type error_reason ::
          :invalid_key_size
          | :invalid_iv_size
          | :invalid_block_size
          | :invalid_padding
          | :unsupported

  # SM4 S-box (256 entries as tuple for O(1) elem/2 access)
  @s_box {
    0xD6,
    0x90,
    0xE9,
    0xFE,
    0xCC,
    0xE1,
    0x3D,
    0xB7,
    0x16,
    0xB6,
    0x14,
    0xC2,
    0x28,
    0xFB,
    0x2C,
    0x05,
    0x2B,
    0x67,
    0x9A,
    0x76,
    0x2A,
    0xBE,
    0x04,
    0xC3,
    0xAA,
    0x44,
    0x13,
    0x26,
    0x49,
    0x86,
    0x06,
    0x99,
    0x9C,
    0x42,
    0x50,
    0xF4,
    0x91,
    0xEF,
    0x98,
    0x7A,
    0x33,
    0x54,
    0x0B,
    0x43,
    0xED,
    0xCF,
    0xAC,
    0x62,
    0xE4,
    0xB3,
    0x1C,
    0xA9,
    0xC9,
    0x08,
    0xE8,
    0x95,
    0x80,
    0xDF,
    0x94,
    0xFA,
    0x75,
    0x8F,
    0x3F,
    0xA6,
    0x47,
    0x07,
    0xA7,
    0xFC,
    0xF3,
    0x73,
    0x17,
    0xBA,
    0x83,
    0x59,
    0x3C,
    0x19,
    0xE6,
    0x85,
    0x4F,
    0xA8,
    0x68,
    0x6B,
    0x81,
    0xB2,
    0x71,
    0x64,
    0xDA,
    0x8B,
    0xF8,
    0xEB,
    0x0F,
    0x4B,
    0x70,
    0x56,
    0x9D,
    0x35,
    0x1E,
    0x24,
    0x0E,
    0x5E,
    0x63,
    0x58,
    0xD1,
    0xA2,
    0x25,
    0x22,
    0x7C,
    0x3B,
    0x01,
    0x21,
    0x78,
    0x87,
    0xD4,
    0x00,
    0x46,
    0x57,
    0x9F,
    0xD3,
    0x27,
    0x52,
    0x4C,
    0x36,
    0x02,
    0xE7,
    0xA0,
    0xC4,
    0xC8,
    0x9E,
    0xEA,
    0xBF,
    0x8A,
    0xD2,
    0x40,
    0xC7,
    0x38,
    0xB5,
    0xA3,
    0xF7,
    0xF2,
    0xCE,
    0xF9,
    0x61,
    0x15,
    0xA1,
    0xE0,
    0xAE,
    0x5D,
    0xA4,
    0x9B,
    0x34,
    0x1A,
    0x55,
    0xAD,
    0x93,
    0x32,
    0x30,
    0xF5,
    0x8C,
    0xB1,
    0xE3,
    0x1D,
    0xF6,
    0xE2,
    0x2E,
    0x82,
    0x66,
    0xCA,
    0x60,
    0xC0,
    0x29,
    0x23,
    0xAB,
    0x0D,
    0x53,
    0x4E,
    0x6F,
    0xD5,
    0xDB,
    0x37,
    0x45,
    0xDE,
    0xFD,
    0x8E,
    0x2F,
    0x03,
    0xFF,
    0x6A,
    0x72,
    0x6D,
    0x6C,
    0x5B,
    0x51,
    0x8D,
    0x1B,
    0xAF,
    0x92,
    0xBB,
    0xDD,
    0xBC,
    0x7F,
    0x11,
    0xD9,
    0x5C,
    0x41,
    0x1F,
    0x10,
    0x5A,
    0xD8,
    0x0A,
    0xC1,
    0x31,
    0x88,
    0xA5,
    0xCD,
    0x7B,
    0xBD,
    0x2D,
    0x74,
    0xD0,
    0x12,
    0xB8,
    0xE5,
    0xB4,
    0xB0,
    0x89,
    0x69,
    0x97,
    0x4A,
    0x0C,
    0x96,
    0x77,
    0x7E,
    0x65,
    0xB9,
    0xF1,
    0x09,
    0xC5,
    0x6E,
    0xC6,
    0x84,
    0x18,
    0xF0,
    0x7D,
    0xEC,
    0x3A,
    0xDC,
    0x4D,
    0x20,
    0x79,
    0xEE,
    0x5F,
    0x3E,
    0xD7,
    0xCB,
    0x39,
    0x48
  }

  @fk {0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC}

  # T0[a] = L(S(a)) for a in 0..255, with the S-box output in the low byte.
  # Because L is linear and rotation-invariant, the round transform becomes
  # four byte-table lookups instead of four S-box lookups plus four rotations:
  #   L(tau(x)) = rotl(T0[x>>>24], 24) ^ rotl(T0[(x>>>16)&&&0xFF], 16)
  #             ^ rotl(T0[(x>>>8)&&&0xFF], 8) ^ T0[x&&&0xFF]
  @t0 (for a <- 0..255 do
         s = elem(@s_box, a)
         r2 = (s <<< 2 ||| s >>> 30) &&& 0xFFFFFFFF
         r10 = (s <<< 10 ||| s >>> 22) &&& 0xFFFFFFFF
         r18 = (s <<< 18 ||| s >>> 14) &&& 0xFFFFFFFF
         r24 = (s <<< 24 ||| s >>> 8) &&& 0xFFFFFFFF
         bxor(s, bxor(r2, bxor(r10, bxor(r18, r24))))
       end)
      |> List.to_tuple()

  # CK[i] = (4i+0)*7 mod 256 || (4i+1)*7 mod 256 || (4i+2)*7 mod 256 || (4i+3)*7 mod 256
  @ck {
    0x00070E15,
    0x1C232A31,
    0x383F464D,
    0x545B6269,
    0x70777E85,
    0x8C939AA1,
    0xA8AFB6BD,
    0xC4CBD2D9,
    0xE0E7EEF5,
    0xFC030A11,
    0x181F262D,
    0x343B4249,
    0x50575E65,
    0x6C737A81,
    0x888F969D,
    0xA4ABB2B9,
    0xC0C7CED5,
    0xDCE3EAF1,
    0xF8FF060D,
    0x141B2229,
    0x30373E45,
    0x4C535A61,
    0x686F767D,
    0x848B9299,
    0xA0A7AEB5,
    0xBCC3CAD1,
    0xD8DFE6ED,
    0xF4FB0209,
    0x10171E25,
    0x2C333A41,
    0x484F565D,
    0x646B7279
  }

  @spec supported?() :: boolean()
  def supported?, do: true

  @spec encrypt(binary(), binary(), keyword()) :: {:ok, binary()} | {:error, error_reason()}
  def encrypt(plaintext, key, opts \\ []) when is_binary(plaintext) and is_binary(key) do
    with :ok <- validate_key(key),
         {:ok, data} <- pad(plaintext, opts) do
      {:ok, ecb_encrypt(data, key)}
    else
      {:error, _} = err -> err
    end
  end

  @spec decrypt(binary(), binary(), keyword()) :: {:ok, binary()} | {:error, error_reason()}
  def decrypt(ciphertext, key, opts \\ []) when is_binary(ciphertext) and is_binary(key) do
    with :ok <- validate_key(key),
         :ok <- validate_block(ciphertext),
         {:ok, pt} <- {:ok, ecb_decrypt(ciphertext, key)},
         {:ok, out} <- unpad(pt, opts) do
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
      {:ok, cbc_encrypt(data, key, iv)}
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
         {:ok, pt} <- {:ok, cbc_decrypt(ciphertext, key, iv)},
         {:ok, out} <- unpad(pt, opts) do
      {:ok, out}
    else
      {:error, _} = err -> err
    end
  end

  @spec encrypt_ctr(binary(), binary(), binary(), keyword()) ::
          {:ok, binary()} | {:error, error_reason()}
  def encrypt_ctr(plaintext, key, counter, opts \\ [])
      when is_binary(plaintext) and is_binary(key) and is_binary(counter) do
    with :ok <- validate_key(key),
         :ok <- validate_iv(counter),
         :ok <- validate_ctr_opts(opts) do
      {:ok, ctr_crypt(plaintext, key, counter)}
    end
  end

  @spec decrypt_ctr(binary(), binary(), binary(), keyword()) ::
          {:ok, binary()} | {:error, error_reason()}
  def decrypt_ctr(ciphertext, key, counter, opts \\ [])
      when is_binary(ciphertext) and is_binary(key) and is_binary(counter) do
    encrypt_ctr(ciphertext, key, counter, opts)
  end

  # -- ECB mode ----------------------------------------------------------------

  defp ecb_encrypt(data, key) do
    rk = expand_key(key)
    for <<block::binary-size(16) <- data>>, into: <<>>, do: crypt_block(block, rk)
  end

  defp ecb_decrypt(data, key) do
    rk = expand_key(key)
    rk_rev = rk |> Tuple.to_list() |> Enum.reverse() |> List.to_tuple()
    for <<block::binary-size(16) <- data>>, into: <<>>, do: crypt_block(block, rk_rev)
  end

  # -- CBC mode ----------------------------------------------------------------

  defp cbc_encrypt(data, key, iv) do
    rk = expand_key(key)

    {_, ct} =
      for <<b::binary-size(16) <- data>>, reduce: {iv, <<>>} do
        {prev, acc} ->
          enc = crypt_block(xor_bytes(b, prev), rk)
          {enc, acc <> enc}
      end

    ct
  end

  defp cbc_decrypt(data, key, iv) do
    rk = expand_key(key)
    rk_rev = rk |> Tuple.to_list() |> Enum.reverse() |> List.to_tuple()

    {_, pt} =
      for <<b::binary-size(16) <- data>>, reduce: {iv, <<>>} do
        {prev, acc} ->
          {b, acc <> xor_bytes(crypt_block(b, rk_rev), prev)}
      end

    pt
  end

  # -- CTR mode ----------------------------------------------------------------

  defp ctr_crypt(data, key, counter) do
    rk = expand_key(key)
    do_ctr_crypt(data, counter, rk, <<>>)
  end

  defp do_ctr_crypt(<<>>, _counter, _rk, acc), do: acc

  defp do_ctr_crypt(data, counter, rk, acc) when byte_size(data) < @block_size do
    size = byte_size(data)
    keystream = crypt_block(counter, rk)
    <<mask::binary-size(size), _::binary>> = keystream
    acc <> xor_bytes(data, mask)
  end

  defp do_ctr_crypt(<<block::binary-size(@block_size), rest::binary>>, counter, rk, acc) do
    do_ctr_crypt(
      rest,
      increment_counter(counter),
      rk,
      acc <> xor_bytes(block, crypt_block(counter, rk))
    )
  end

  defp increment_counter(<<counter::128-big>>) do
    <<rem(counter + 1, 1 <<< 128)::128-big>>
  end

  defp xor_bytes(a, b), do: :crypto.exor(a, b)

  # -- Key expansion -----------------------------------------------------------

  defp expand_key(<<mk0::32-big, mk1::32-big, mk2::32-big, mk3::32-big>>) do
    {fk0, fk1, fk2, fk3} = @fk
    k0 = bxor(mk0, fk0)
    k1 = bxor(mk1, fk1)
    k2 = bxor(mk2, fk2)
    k3 = bxor(mk3, fk3)
    expand(k0, k1, k2, k3, 0, [])
  end

  defp expand(_k0, _k1, _k2, _k3, i, acc) when i > 31,
    do: acc |> Enum.reverse() |> List.to_tuple()

  defp expand(k0, k1, k2, k3, i, acc) do
    x = bxor(bxor(bxor(k1, k2), k3), elem(@ck, i))
    rk = bxor(k0, l_prime(tau(x)))
    expand(k1, k2, k3, rk, i + 1, [rk | acc])
  end

  # -- SM4 round function (32 rounds) ------------------------------------------

  defp crypt_block(<<x0::32-big, x1::32-big, x2::32-big, x3::32-big>>, rk) do
    {x35, x34, x33, x32} = rounds(x0, x1, x2, x3, rk, 0)
    <<x35::32-big, x34::32-big, x33::32-big, x32::32-big>>
  end

  defp rounds(x0, x1, x2, x3, _rk, i) when i > 31, do: {x3, x2, x1, x0}

  defp rounds(x0, x1, x2, x3, rk, i) do
    x4 = bxor(x0, t_lookup(bxor(bxor(bxor(x1, x2), x3), elem(rk, i))))
    rounds(x1, x2, x3, x4, rk, i + 1)
  end

  # -- tau + L fused into byte-table lookups (see @t0) -------------------------

  defp t_lookup(x) do
    bxor(
      bxor(rotl24(elem(@t0, x >>> 24)), rotl16(elem(@t0, x >>> 16 &&& 0xFF))),
      bxor(rotl8(elem(@t0, x >>> 8 &&& 0xFF)), elem(@t0, x &&& 0xFF))
    )
  end

  # -- tau: S-box substitution on 4 bytes of a 32-bit word ---------------------

  defp tau(w) do
    b0 = w >>> 24 &&& 0xFF
    b1 = w >>> 16 &&& 0xFF
    b2 = w >>> 8 &&& 0xFF
    b3 = w &&& 0xFF
    s0 = elem(@s_box, b0)
    s1 = elem(@s_box, b1)
    s2 = elem(@s_box, b2)
    s3 = elem(@s_box, b3)
    s0 <<< 24 ||| s1 <<< 16 ||| s2 <<< 8 ||| s3
  end

  # -- Linear transforms -------------------------------------------------------

  defp l_prime(b) do
    bxor(b, bxor(rotl(b, 13), rotl(b, 23)))
  end

  defp rotl8(x), do: (x <<< 8 ||| x >>> 24) &&& 0xFFFFFFFF
  defp rotl16(x), do: (x <<< 16 ||| x >>> 16) &&& 0xFFFFFFFF
  defp rotl24(x), do: (x <<< 24 ||| x >>> 8) &&& 0xFFFFFFFF

  defp rotl(x, n) do
    s = rem(n, 32)
    (x <<< s ||| x >>> (32 - s)) &&& 0xFFFFFFFF
  end

  # -- Validation --------------------------------------------------------------

  defp validate_key(<<_::binary-size(@key_size)>>), do: :ok
  defp validate_key(_), do: {:error, :invalid_key_size}

  defp validate_iv(<<_::binary-size(@block_size)>>), do: :ok
  defp validate_iv(_), do: {:error, :invalid_iv_size}

  defp validate_block(data) when rem(byte_size(data), @block_size) == 0, do: :ok
  defp validate_block(_), do: {:error, :invalid_block_size}

  defp validate_ctr_opts([]), do: :ok
  defp validate_ctr_opts(_), do: {:error, :invalid_padding}

  # -- PKCS#7 padding ----------------------------------------------------------

  defp pad(data, opts) do
    case Keyword.get(opts, :padding, :pkcs7) do
      :none ->
        if rem(byte_size(data), @block_size) == 0,
          do: {:ok, data},
          else: {:error, :invalid_block_size}

      :pkcs7 ->
        pl = pkcs7_len(byte_size(data))
        {:ok, data <> :binary.copy(<<pl>>, pl)}

      _ ->
        {:error, :invalid_padding}
    end
  end

  defp pkcs7_len(sz) do
    r = rem(sz, @block_size)
    if r == 0, do: @block_size, else: @block_size - r
  end

  defp unpad(data, opts) do
    case Keyword.get(opts, :padding, :pkcs7) do
      :none -> {:ok, data}
      :pkcs7 -> do_unpad(data)
      _ -> {:error, :invalid_padding}
    end
  end

  defp do_unpad(<<>>), do: {:error, :invalid_padding}

  defp do_unpad(data) do
    pl = :binary.last(data)

    if pl < 1 or pl > @block_size or pl > byte_size(data) do
      {:error, :invalid_padding}
    else
      check_padding(data, pl)
    end
  end

  defp check_padding(data, pl) do
    sz = byte_size(data)
    <<body::binary-size(sz - pl), pad::binary-size(pl)>> = data

    if pad == :binary.copy(<<pl>>, pl) do
      {:ok, body}
    else
      {:error, :invalid_padding}
    end
  end
end
