defmodule Guomi.SM2.Curve do
  @moduledoc false

  # SM2 curve parameters (sm2p256v1, GM/T 0003-2012)
  @p 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
  @n 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
  @a 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
  @b 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
  @gx 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
  @gy 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

  # -- Field operations -------------------------------------------------------

  defp mod_add(a, b), do: mod(a + b, @p)
  defp mod_sub(a, b), do: mod(a - b, @p)
  defp mod_mul(a, b), do: mod(a * b, @p)

  defp scalar_add(a, b), do: mod(a + b, @n)
  defp scalar_sub(a, b), do: mod(a - b, @n)
  defp scalar_mul(a, b), do: mod(a * b, @n)

  defp mod(value, modulus) do
    value
    |> rem(modulus)
    |> Kernel.+(modulus)
    |> rem(modulus)
  end

  # Modular inverse using extended Euclidean algorithm (iterative)
  def mod_inv(a, modulus \\ @p) do
    a = mod(a, modulus)
    if a == 0, do: 0, else: egcd_iter(0, 1, modulus, a, modulus)
  end

  # Iterative extended GCD to avoid stack overflow from deep recursion
  defp egcd_iter(t, _new_t, _r, 0, modulus), do: mod(t, modulus)

  defp egcd_iter(t, new_t, r, new_r, modulus) do
    quotient = div(r, new_r)
    egcd_iter(new_t, t - quotient * new_t, new_r, r - quotient * new_r, modulus)
  end

  # -- Curve queries ----------------------------------------------------------

  def a, do: @a
  def b, do: @b
  def n, do: @n
  def p, do: @p
  def generator, do: {@gx, @gy}

  # -- Point operations in affine coordinates ---------------------------------

  def neg(:infinity), do: :infinity
  def neg({x, y}), do: {x, mod_sub(0, y)}

  # -- Scalar multiplication ---------------------------------------------------

  # Public entry point: returns affine point
  def mul(:infinity, _k), do: :infinity
  def mul(_p, 0), do: :infinity
  def mul(point, k) when k < 0, do: mul(neg(point), -k)

  def mul(point, k) do
    k_mod = rem(k, @n)

    if k_mod == 0 do
      :infinity
    else
      k_mod
      |> mul_jac(to_jacobian(point), {0, 1, 0})
      |> from_jacobian()
    end
  end

  defp mul_jac(0, _point, acc), do: acc

  defp mul_jac(k, point, acc) do
    acc = if Bitwise.band(k, 1) == 1, do: jac_add(acc, point), else: acc
    mul_jac(Bitwise.bsr(k, 1), jac_double(point), acc)
  end

  # Jacobian coordinates avoid a modular inverse for every intermediate point
  # operation. Only the final conversion back to affine coordinates needs one.
  defp to_jacobian({x, y}), do: {x, y, 1}

  defp from_jacobian({_x, _y, 0}), do: :infinity

  defp from_jacobian({x, y, z}) do
    z_inv = mod_inv(z)
    z_inv_sq = mod_mul(z_inv, z_inv)
    {mod_mul(x, z_inv_sq), mod_mul(y, mod_mul(z_inv_sq, z_inv))}
  end

  defp jac_double({_x, 0, _z}), do: {0, 1, 0}
  defp jac_double({_x, _y, 0}), do: {0, 1, 0}

  defp jac_double({x, y, z}) do
    xx = mod_mul(x, x)
    yy = mod_mul(y, y)
    yyyy = mod_mul(yy, yy)
    zz = mod_mul(z, z)
    s = mod_mul(4, mod_mul(x, yy))
    m = mod_add(mod_mul(3, xx), mod_mul(@a, mod_mul(zz, zz)))
    x3 = mod_sub(mod_mul(m, m), mod_mul(2, s))
    y3 = mod_sub(mod_mul(m, mod_sub(s, x3)), mod_mul(8, yyyy))
    z3 = mod_mul(2, mod_mul(y, z))
    {x3, y3, z3}
  end

  defp jac_add({_x, _y, 0}, point), do: point
  defp jac_add(point, {_x, _y, 0}), do: point

  defp jac_add({x1, y1, z1} = p1, {x2, y2, z2}) do
    z1_sq = mod_mul(z1, z1)
    z2_sq = mod_mul(z2, z2)
    u1 = mod_mul(x1, z2_sq)
    u2 = mod_mul(x2, z1_sq)
    s1 = mod_mul(y1, mod_mul(z2, z2_sq))
    s2 = mod_mul(y2, mod_mul(z1, z1_sq))

    cond do
      u1 != u2 -> jac_add_distinct(u1, u2, s1, s2, z1, z2)
      s1 == s2 -> jac_double(p1)
      true -> {0, 1, 0}
    end
  end

  defp jac_add_distinct(u1, u2, s1, s2, z1, z2) do
    h = mod_sub(u2, u1)
    r = mod_sub(s2, s1)
    h_sq = mod_mul(h, h)
    h_cubed = mod_mul(h, h_sq)
    u1_h_sq = mod_mul(u1, h_sq)
    x3 = mod_sub(mod_sub(mod_mul(r, r), h_cubed), mod_mul(2, u1_h_sq))
    y3 = mod_sub(mod_mul(r, mod_sub(u1_h_sq, x3)), mod_mul(s1, h_cubed))
    z3 = mod_mul(h, mod_mul(z1, z2))
    {x3, y3, z3}
  end

  # -- Encoding / Decoding ----------------------------------------------------

  def encode_public({x, y}) do
    <<0x04, x::256-big, y::256-big>>
  end

  def decode_public(<<0x04, x::32-binary, y::32-binary>>) do
    {:binary.decode_unsigned(x, :big), :binary.decode_unsigned(y, :big)}
  end

  def decode_public(<<0x04, rest::binary>>) when byte_size(rest) == 64 do
    <<x::32-binary, y::32-binary>> = rest
    {:binary.decode_unsigned(x, :big), :binary.decode_unsigned(y, :big)}
  end

  def encode_signature(r, s), do: <<r::256-big, s::256-big>>

  def decode_signature(<<r::32-binary, s::32-binary>>) do
    {:binary.decode_unsigned(r, :big), :binary.decode_unsigned(s, :big)}
  end

  # -- Key generation ---------------------------------------------------------

  def generate_private_key do
    bytes = :crypto.strong_rand_bytes(32)
    k = :binary.decode_unsigned(bytes, :big)
    if k == 0, do: generate_private_key(), else: rem(k, @n - 1) + 1
  end

  def generate_keypair do
    priv = generate_private_key()
    pub = mul(generator(), priv)
    {priv, pub}
  end

  # -- ECDH shared secret -----------------------------------------------------

  def shared_secret(private_key, <<0x04, x::32-binary, y::32-binary>>) do
    px = :binary.decode_unsigned(x, :big)
    py = :binary.decode_unsigned(y, :big)
    shared_secret(private_key, {px, py})
  end

  def shared_secret(private_key, public_point) do
    case mul(public_point, private_key) do
      :infinity -> {:error, :decryption_failed}
      {sx, _sy} -> {:ok, sx}
    end
  end

  # -- ECDSA signature (SM2 variant) ------------------------------------------

  def sign(message_hash, private_key) do
    e = :binary.decode_unsigned(message_hash, :big)
    sign_with_e(e, private_key)
  end

  defp sign_with_e(e, d) do
    k = generate_k()
    {x1, _y1} = mul(generator(), k)
    r = scalar_add(e, x1)

    if r == 0 or r + k == @n do
      sign_with_e(e, d)
    else
      s = scalar_mul(mod_inv(1 + d, @n), scalar_sub(k, scalar_mul(r, d)))
      if s == 0, do: sign_with_e(e, d), else: {:ok, encode_signature(r, s)}
    end
  end

  defp generate_k do
    bytes = :crypto.strong_rand_bytes(32)
    k = :binary.decode_unsigned(bytes, :big)
    if k == 0, do: generate_k(), else: rem(k, @n - 1) + 1
  end

  def verify(message_hash, signature, public_key) do
    {r, s} = decode_signature(signature)
    e = :binary.decode_unsigned(message_hash, :big)
    verify_with_e(e, r, s, public_key)
  end

  defp verify_with_e(e, r, s, public_key) do
    cond do
      r < 1 or r >= @n ->
        false

      s < 1 or s >= @n ->
        false

      true ->
        verify_valid_signature(e, r, s, public_key)
    end
  end

  defp verify_valid_signature(e, r, s, public_key) do
    case scalar_add(r, s) do
      0 ->
        false

      t ->
        verify_signature_point(e, r, s, public_key, t)
    end
  end

  defp verify_signature_point(e, r, s, public_key, t) do
    p1 = mul(generator(), s)
    p2 = mul(public_key, t)

    case add_aff(p1, p2) do
      :infinity -> false
      {x1, _y1} -> scalar_add(e, x1) == r
    end
  end

  # Fallback affine addition for verify (not performance-critical)
  defp add_aff(:infinity, q), do: q
  defp add_aff(p, :infinity), do: p
  defp add_aff({x1, y1}, {x2, y2}) when x1 == x2 and rem(y1 + y2, @p) == 0, do: :infinity

  defp add_aff({x, y}, {x, y}) do
    lam = mod_mul(mod_sub(mod_mul(3, mod_mul(x, x)), 3), mod_inv(mod_mul(2, y)))
    x3 = mod_sub(mod_mul(lam, lam), mod_mul(2, x))
    y3 = mod_sub(mod_mul(lam, mod_sub(x, x3)), y)
    {x3, y3}
  end

  defp add_aff({x1, y1}, {x2, y2}) do
    lam = mod_mul(mod_sub(y2, y1), mod_inv(mod_sub(x2, x1)))
    x3 = mod_sub(mod_sub(mod_mul(lam, lam), x1), x2)
    y3 = mod_sub(mod_mul(lam, mod_sub(x1, x3)), y1)
    {x3, y3}
  end

  def private_key_to_int(key_bin) when byte_size(key_bin) == 32 do
    :binary.decode_unsigned(key_bin, :big)
  end
end
