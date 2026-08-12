defmodule Guomi.SM3 do
  import Bitwise

  @moduledoc """
  Pure Elixir SM3 cryptographic hash implementation.

  SM3 is a Chinese national standard hash function (GM/T 0004-2012) producing
  256-bit digests. This is a pure Elixir implementation with no external dependencies.
  """

  @type input :: binary() | iodata()

  # Initial values (8 x 32-bit words)
  @iv {0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D,
       0xB0FB0E4E}

  # T_j' = rotl(T_j, j) for j = 0..63, precomputed once at compile time.
  # rotl wraps at 32 bits, so the shift amount is reduced mod 32 first.
  @tj (for j <- 0..63 do
         t = if j <= 15, do: 0x79CC4519, else: 0x7A879D8A
         s = rem(j, 32)
         (t <<< s ||| t >>> (32 - s)) &&& 0xFFFFFFFF
       end)
      |> List.to_tuple()

  @spec supported?() :: boolean()
  @doc "Returns `true`; SM3 is implemented entirely in Elixir."
  def supported?, do: true

  @spec hash(input()) :: binary()
  @doc """
  Hashes binary or iodata input and returns the 32-byte SM3 digest.

  Raises `ArgumentError` when `data` is not valid iodata.
  """
  def hash(data) when is_binary(data), do: do_hash(data)
  def hash(data), do: data |> IO.iodata_to_binary() |> do_hash()

  @spec hash_hex(input()) :: String.t()
  @doc """
  Hashes binary or iodata input and returns a 64-character lowercase hex digest.

  Raises `ArgumentError` when `data` is not valid iodata.

  ## Example

      iex> Guomi.SM3.hash_hex("abc")
      "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
  """
  def hash_hex(data) do
    data |> hash() |> Base.encode16(case: :lower)
  end

  # ---------------------------------------------------------------------------
  # Padding (identical to SHA-256: 0x80 || 0* || 64-bit bit-length)
  # ---------------------------------------------------------------------------

  defp do_hash(data) do
    data
    |> pad()
    |> process_blocks(@iv)
    |> to_binary()
  end

  defp pad(data) do
    bit_len = byte_size(data) * 8
    padded = data <> <<0x80>>
    pad_len = rem(64 - rem(byte_size(padded) + 8, 64), 64)
    padded <> :binary.copy(<<0>>, pad_len) <> <<bit_len::64-big>>
  end

  # ---------------------------------------------------------------------------
  # Block processing
  # ---------------------------------------------------------------------------

  defp process_blocks(<<>>, state), do: state

  defp process_blocks(<<block::binary-size(64), rest::binary>>, state) do
    process_blocks(rest, compress(state, block))
  end

  # ---------------------------------------------------------------------------
  # Compression function
  # ---------------------------------------------------------------------------

  defp compress(state, block) do
    # Message words W[0..15] become the rolling window, newest first:
    # window = (W[j+15], W[j+14], ..., W[j]) at round j.
    <<w0::32-big, w1::32-big, w2::32-big, w3::32-big, w4::32-big, w5::32-big, w6::32-big,
      w7::32-big, w8::32-big, w9::32-big, w10::32-big, w11::32-big, w12::32-big, w13::32-big,
      w14::32-big, w15::32-big>> = block

    window = {w15, w14, w13, w12, w11, w10, w9, w8, w7, w6, w5, w4, w3, w2, w1, w0}

    state |> round_function(window, 0) |> bxor_state(state)
  end

  defp bxor_state({a, b, c, d, e, f, g, h}, {na, nb, nc, nd, ne, nf, ng, nh}) do
    {bxor(a, na), bxor(b, nb), bxor(c, nc), bxor(d, nd), bxor(e, ne), bxor(f, nf), bxor(g, ng),
     bxor(h, nh)}
  end

  # ---------------------------------------------------------------------------
  # 64-round compression with rolling message expansion
  #
  # The 16-word window (W[j+15], ..., W[j]) is carried through the rounds and
  # shifted by one each iteration, so the expanded words W[16..67] are computed
  # on demand with no separate expansion pass and no random-access structure.
  # ---------------------------------------------------------------------------

  defp round_function(state, _window, j) when j > 63, do: state

  defp round_function(
         {a, b, c, d, e, f, g, h},
         {w15, w14, w13, w12, w11, w10, w9, w8, w7, w6, w5, w4, w3, w2, w1, w0},
         j
       ) do
    ss1 = rotl7(add32(add32(rotl12(a), e), elem(@tj, j)))
    ss2 = bxor(ss1, rotl12(a))

    # W'[j] = W[j] XOR W[j+4]
    wp = bxor(w0, w4)

    tt1 = add32(add32(add32(ff(a, b, c, j), d), ss2), wp)
    tt2 = add32(add32(add32(gg(e, f, g, j), h), ss1), w0)

    # W[j+16] = P1(W[j] ^ W[j+7] ^ rotl(W[j+13], 15)) ^ rotl(W[j+3], 7) ^ W[j+10]
    w_new = bxor(bxor(p1(bxor(bxor(w0, w7), rotl15(w13))), rotl7(w3)), w10)

    round_function(
      {tt1, a, rotl9(b), c, p0(tt2), e, rotl19(f), g},
      {w_new, w15, w14, w13, w12, w11, w10, w9, w8, w7, w6, w5, w4, w3, w2, w1},
      j + 1
    )
  end

  # ---------------------------------------------------------------------------
  # Boolean functions FF_j and GG_j
  # ---------------------------------------------------------------------------

  defp ff(x, y, z, j) when j <= 15, do: bxor(x, bxor(y, z))
  defp ff(x, y, z, _j), do: bor(bor(band(x, y), band(x, z)), band(y, z))

  defp gg(x, y, z, j) when j <= 15, do: bxor(x, bxor(y, z))
  defp gg(x, y, z, _j), do: bor(band(x, y), band(bnot(x) &&& 0xFFFFFFFF, z))

  # ---------------------------------------------------------------------------
  # Permutation functions
  # ---------------------------------------------------------------------------

  defp p0(x), do: bxor(x, bxor(rotl9(x), rotl17(x)))
  defp p1(x), do: bxor(x, bxor(rotl15(x), rotl23(x)))

  # ---------------------------------------------------------------------------
  # Bitwise helpers (32-bit word operations)
  #
  # Specialized rotations: every shift amount is a compile-time constant, so a
  # fixed pattern avoids the rem/2 and dynamic-shift overhead of rotl/2.
  # ---------------------------------------------------------------------------

  defp rotl7(x), do: (x <<< 7 ||| x >>> 25) &&& 0xFFFFFFFF
  defp rotl9(x), do: (x <<< 9 ||| x >>> 23) &&& 0xFFFFFFFF
  defp rotl12(x), do: (x <<< 12 ||| x >>> 20) &&& 0xFFFFFFFF
  defp rotl15(x), do: (x <<< 15 ||| x >>> 17) &&& 0xFFFFFFFF
  defp rotl17(x), do: (x <<< 17 ||| x >>> 15) &&& 0xFFFFFFFF
  defp rotl19(x), do: (x <<< 19 ||| x >>> 13) &&& 0xFFFFFFFF
  defp rotl23(x), do: (x <<< 23 ||| x >>> 9) &&& 0xFFFFFFFF
  defp add32(a, b), do: a + b &&& 0xFFFFFFFF

  # ---------------------------------------------------------------------------
  # Final output: 8 words -> 32 bytes big-endian
  # ---------------------------------------------------------------------------

  defp to_binary({a, b, c, d, e, f, g, h}) do
    <<a::32-big, b::32-big, c::32-big, d::32-big, e::32-big, f::32-big, g::32-big, h::32-big>>
  end
end
