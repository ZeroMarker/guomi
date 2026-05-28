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

  defp mod_add(a, b), do: rem(a + b, @p)
  defp mod_sub(a, b), do: rem(a - b + @p, @p)
  defp mod_mul(a, b), do: rem(a * b, @p)

  # Modular inverse using extended Euclidean algorithm (iterative)
  def mod_inv(a) do
    a = rem(a, @p)
    if a == 0, do: 0, else: egcd_iter(@p, a)
  end

  # Iterative extended GCD to avoid stack overflow from deep recursion
  defp egcd_iter(_, 0), do: 1

  defp egcd_iter(a, b) do
    egcd_iter(a, b, 0, 1, 1, 0)
  end

  defp egcd_iter(_a, 0, _s1, s2, _t1, _t2), do: s2 |> adjust()

  defp egcd_iter(a, b, s1, s2, t1, t2) do
    q = div(a, b)
    egcd_iter(b, rem(a, b), s2, s1 - q * s2, t2, t1 - q * t2)
  end

  defp adjust(x) when x < 0, do: x + @p
  defp adjust(x), do: x

  # -- Curve queries ----------------------------------------------------------

  def a, do: @a
  def b, do: @b
  def n, do: @n
  def p, do: @p
  def generator, do: {@gx, @gy}

  # -- Point operations in affine coordinates ---------------------------------

  def neg(:infinity), do: :infinity
  def neg({x, y}), do: {x, mod_sub(0, y)}

  # -- Jacobian projective coordinates ----------------------------------------
  # (X, Y, Z) corresponding to affine (X/Z², Y/Z³)
  # :infinity for the point at infinity (Z = 0)

  defp to_jac(:infinity), do: :infinity
  defp to_jac({x, y}), do: {x, y, 1}

  # Convert Jacobian back to affine. If Z = 0, return :infinity.
  defp to_aff(:infinity), do: :infinity
  defp to_aff({_x, _y, 0}), do: :infinity

  defp to_aff({x, y, z}) do
    z_inv = mod_inv(z)
    z_inv_sq = mod_mul(z_inv, z_inv)
    x_aff = mod_mul(x, z_inv_sq)
    y_aff = mod_mul(y, mod_mul(z_inv, z_inv_sq))
    {x_aff, y_aff}
  end

  # Jacobian point doubling (for curves with a = -3)
  # M = 3*(X1 - Z1²)*(X1 + Z1²) = 3*(X1² - Z1⁴)
  defp jac_double(:infinity), do: :infinity

  defp jac_double({x1, y1, z1}) do
    # When y1 == 0, doubling gives point at infinity
    if y1 == 0, do: :infinity, else: jac_double_impl(x1, y1, z1)
  end

  defp jac_double_impl(x1, y1, z1) do
    # Using formulas optimized for a = -3 (a = p - 3 for SM2)
    # Y1²
    t1 = mod_mul(y1, y1)
    # X1 * Y1²
    t2 = mod_mul(x1, t1)
    # S = 4 * X1 * Y1²
    t2 = mod_mul(4, t2)
    # (Y1²)²
    t3 = mod_mul(t1, t1)
    # Z1²
    t1 = mod_mul(z1, z1)
    # X1 - Z1²
    t4 = mod_sub(x1, t1)
    # X1 + Z1²
    t1 = mod_add(x1, t1)
    # X1² - Z1⁴
    t4 = mod_mul(t4, t1)
    # M = 3*(X1² - Z1⁴)  [a=-3 case]
    t4 = mod_mul(3, t4)

    # M²
    t1 = mod_mul(t4, t4)
    # 2*S
    t5 = mod_mul(2, t2)
    # X3 = M² - 2*S
    x3 = mod_sub(t1, t5)

    # S - X3
    t1 = mod_sub(t2, x3)
    # M*(S - X3)
    t1 = mod_mul(t4, t1)
    # 8*(Y1²)²
    t3 = mod_mul(8, t3)
    # Y3 = M*(S - X3) - 8*Y1⁴
    y3 = mod_sub(t1, t3)

    # Y1*Z1
    t1 = mod_mul(y1, z1)
    # Z3 = 2*Y1*Z1
    z3 = mod_mul(2, t1)

    {x3, y3, z3}
  end

  # Mixed Jacobian + affine addition: P in Jacobian, Q in affine (Z2 = 1)
  defp jac_add(:infinity, q), do: to_jac(q)
  defp jac_add(p, :infinity), do: p

  defp jac_add({x1, y1, z1}, {x2, y2}) do
    jac_add_impl(x1, y1, z1, x2, y2)
  end

  defp jac_add_impl(x1, y1, z1, x2, y2) do
    # Z1²
    z1_sq = mod_mul(z1, z1)
    # Z1³
    z1_cu = mod_mul(z1_sq, z1)

    # U2 = X2*Z1²
    u2 = mod_mul(x2, z1_sq)
    # S2 = Y2*Z1³
    s2 = mod_mul(y2, z1_cu)
    # H = U2 - U1 (U1 = X1)
    h = mod_sub(u2, x1)
    # R = S2 - S1 (S1 = Y1)
    r = mod_sub(s2, y1)

    if h == 0 do
      if r == 0 do
        jac_double({x1, y1, z1})
      else
        :infinity
      end
    else
      # H²
      h_sq = mod_mul(h, h)
      # H³
      h_cu = mod_mul(h_sq, h)
      # U1*H²
      u1_h_sq = mod_mul(x1, h_sq)

      x3 = mod_sub(mod_sub(mod_mul(r, r), h_cu), mod_mul(2, u1_h_sq))
      y3 = mod_sub(mod_mul(r, mod_sub(u1_h_sq, x3)), mod_mul(y1, h_cu))
      z3 = mod_mul(h, z1)

      {x3, y3, z3}
    end
  end

  # -- Scalar multiplication using Jacobian coordinates -----------------------

  # Public entry point: returns affine point
  def mul(:infinity, _k), do: :infinity
  def mul(_p, 0), do: :infinity
  def mul(point, k) when k < 0, do: mul(neg(point), -k)

  def mul(point, k) do
    k_mod = rem(k, @n)
    if k_mod == 0, do: :infinity, else: mul_jac(k_mod, to_jac(point)) |> to_aff()
  end

  # Left-to-right double-and-add using Jacobian coordinates
  # Q = infinity, for each bit of k starting from MSB:
  #   Q = double(Q)
  #   if bit == 1: Q = add(Q, P)
  defp mul_jac(k, point) do
    mul_jac_bits(k, point, :infinity, bit_length(k) - 1)
  end

  defp mul_jac_bits(_k, _point, result, -1), do: result

  defp mul_jac_bits(k, point, result, i) do
    result = jac_double(result)
    result = if bit_set?(k, i), do: jac_add(result, point), else: result
    mul_jac_bits(k, point, result, i - 1)
  end

  defp bit_length(0), do: 0
  defp bit_length(n) when n > 0, do: bit_length(n, 0)

  defp bit_length(0, acc), do: acc
  defp bit_length(n, acc), do: bit_length(Bitwise.bsr(n, 1), acc + 1)

  defp bit_set?(k, i), do: Bitwise.band(Bitwise.bsr(k, i), 1) == 1

  # -- Encoding / Decoding ----------------------------------------------------

  def encode_public({x, y}) do
    <<0x04, x::32-binary, y::32-binary>>
  end

  def decode_public(<<0x04, x::32-binary, y::32-binary>>) do
    {:binary.decode_unsigned(x, :big), :binary.decode_unsigned(y, :big)}
  end

  def decode_public(<<0x04, rest::binary>>) when byte_size(rest) == 64 do
    <<x::32-binary, y::32-binary>> = rest
    {:binary.decode_unsigned(x, :big), :binary.decode_unsigned(y, :big)}
  end

  def encode_signature(r, s), do: <<r::32-binary, s::32-binary>>

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
    r = rem(e + x1, @n)

    if r == 0 or r + k == @n do
      sign_with_e(e, d)
    else
      s = mod_mul(mod_inv(1 + d), mod_sub(k, mod_mul(r, d)))
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
        t = rem(r + s, @n)

        if t == 0 do
          false
        else
          p1 = mul(generator(), s)
          p2 = mul(public_key, t)
          {x1, _y1} = add_aff(p1, p2)
          rem(e + x1, @n) == r
        end
    end
  end

  # Fallback affine addition for verify (not performance-critical)
  defp add_aff(:infinity, q), do: q
  defp add_aff(p, :infinity), do: p
  defp add_aff({x1, y1}, {x2, y2}) when x1 == x2 and rem(y1 + y2, @p) == 0, do: :infinity

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
