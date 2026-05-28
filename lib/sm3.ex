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

  @spec supported?() :: boolean()
  def supported?, do: true

  @spec hash(input()) :: binary()
  def hash(data) when is_binary(data), do: do_hash(data)
  def hash(data), do: data |> IO.iodata_to_binary() |> do_hash()

  @spec hash_hex(input()) :: String.t()
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
    # Expand W[0..67] as a map
    w = expand_w(block)

    new_state = round_function(state, w, 0)

    bxor_state(state, new_state)
  end

  defp bxor_state({a, b, c, d, e, f, g, h}, {na, nb, nc, nd, ne, nf, ng, nh}) do
    {bxor(a, na), bxor(b, nb), bxor(c, nc), bxor(d, nd), bxor(e, ne), bxor(f, nf), bxor(g, ng),
     bxor(h, nh)}
  end

  # ---------------------------------------------------------------------------
  # Message expansion: W[0..67] (stored as a map for random access)
  # ---------------------------------------------------------------------------

  defp expand_w(
         <<w0::32-big, w1::32-big, w2::32-big, w3::32-big, w4::32-big, w5::32-big, w6::32-big,
           w7::32-big, w8::32-big, w9::32-big, w10::32-big, w11::32-big, w12::32-big, w13::32-big,
           w14::32-big, w15::32-big, _::binary>>
       ) do
    w = %{
      0 => w0,
      1 => w1,
      2 => w2,
      3 => w3,
      4 => w4,
      5 => w5,
      6 => w6,
      7 => w7,
      8 => w8,
      9 => w9,
      10 => w10,
      11 => w11,
      12 => w12,
      13 => w13,
      14 => w14,
      15 => w15
    }

    expand_w(w, 16)
  end

  defp expand_w(w, j) when j > 67, do: w

  defp expand_w(w, j) do
    wj = bxor(bxor(Map.fetch!(w, j - 16), Map.fetch!(w, j - 9)), rotl(Map.fetch!(w, j - 3), 15))
    wj = bxor(bxor(p1(wj), rotl(Map.fetch!(w, j - 13), 7)), Map.fetch!(w, j - 6))
    expand_w(Map.put(w, j, wj), j + 1)
  end

  # ---------------------------------------------------------------------------
  # 64-round compression
  # ---------------------------------------------------------------------------

  defp round_function(state, _w, j) when j > 63, do: state

  defp round_function({a, b, c, d, e, f, g, h}, w, j) do
    tj = if j <= 15, do: 0x79CC4519, else: 0x7A879D8A

    ss1 = rotl(add32(add32(rotl(a, 12), e), rotl(tj, j)), 7)
    ss2 = bxor(ss1, rotl(a, 12))

    # W'[j] = W[j] XOR W[j+4]
    wp = bxor(Map.fetch!(w, j), Map.fetch!(w, j + 4))

    tt1 = add32(add32(add32(ff(a, b, c, j), d), ss2), wp)
    tt2 = add32(add32(add32(gg(e, f, g, j), h), ss1), Map.fetch!(w, j))

    round_function({tt1, a, rotl(b, 9), c, p0(tt2), e, rotl(f, 19), g}, w, j + 1)
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

  defp p0(x), do: bxor(x, bxor(rotl(x, 9), rotl(x, 17)))
  defp p1(x), do: bxor(x, bxor(rotl(x, 15), rotl(x, 23)))

  # ---------------------------------------------------------------------------
  # Bitwise helpers (32-bit word operations)
  # ---------------------------------------------------------------------------

  defp rotl(x, n), do: (x <<< rem(n, 32) ||| x >>> (32 - rem(n, 32))) &&& 0xFFFFFFFF
  defp add32(a, b), do: a + b &&& 0xFFFFFFFF

  # ---------------------------------------------------------------------------
  # Final output: 8 words -> 32 bytes big-endian
  # ---------------------------------------------------------------------------

  defp to_binary({a, b, c, d, e, f, g, h}) do
    <<a::32-big, b::32-big, c::32-big, d::32-big, e::32-big, f::32-big, g::32-big, h::32-big>>
  end
end
