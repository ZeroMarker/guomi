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

  # -- Point operations in Jacobian coordinates -------------------------------
  #
  # Jacobian point (X, Y, Z) represents affine (X/Z^2, Y/Z^3); the point at
  # infinity is (1, 1, 0). Working in Jacobian coordinates defers the modular
  # inversion to a single conversion at the end, which is the dominant cost in
  # affine double-and-add (one extended-Euclid per point operation).

  def neg(:infinity), do: :infinity
  def neg({x, y}), do: {x, mod_sub(0, y)}

  # Doubling, specialized for a = p - 3 (SM2's curve coefficient):
  #   M = 3*X^2 + a*Z^4 = 3*(X^2 - Z^4)
  defp jac_double({x, y, z}) do
    if z == 0 do
      {1, 1, 0}
    else
      a = mod_mul(x, x)
      b = mod_mul(y, y)
      c = mod_mul(b, b)
      s = mod_mul(4, mod_mul(x, b))
      zz = mod_mul(z, z)
      m = mod_sub(mod_mul(3, a), mod_mul(3, mod_mul(zz, zz)))
      x3 = mod_sub(mod_mul(m, m), mod_mul(2, s))
      y3 = mod_sub(mod_mul(m, mod_sub(s, x3)), mod_mul(8, c))
      z3 = mod_mul(2, mod_mul(y, z))
      {x3, y3, z3}
    end
  end

  # Mixed addition: P (Jacobian) + Q (affine {x2, y2}, Z2 = 1)
  defp jac_add_mixed({_x, _y, 0}, {x2, y2}), do: {x2, y2, 1}

  defp jac_add_mixed({x1, y1, z1}, {x2, y2}) do
    z1z1 = mod_mul(z1, z1)
    u2 = mod_mul(x2, z1z1)
    s2 = mod_mul(y2, mod_mul(z1, z1z1))
    h = mod_sub(u2, x1)
    r = mod_mul(2, mod_sub(s2, y1))

    cond do
      h == 0 and r == 0 ->
        jac_double({x1, y1, z1})

      h == 0 ->
        {1, 1, 0}

      true ->
        i = mod_mul(mod_mul(2, h), mod_mul(2, h))
        j = mod_mul(h, i)
        v = mod_mul(x1, i)
        x3 = mod_sub(mod_sub(mod_mul(r, r), j), mod_mul(2, v))
        y3 = mod_sub(mod_mul(r, mod_sub(v, x3)), mod_mul(2, mod_mul(y1, j)))
        z3 = mod_mul(2, mod_mul(z1, h))
        {x3, y3, z3}
    end
  end

  defp jac_to_affine({_x, _y, 0}), do: :infinity

  defp jac_to_affine({x, y, z}) do
    z_inv = mod_inv(z, @p)
    z2 = mod_mul(z_inv, z_inv)
    {mod_mul(x, z2), mod_mul(y, mod_mul(z2, z_inv))}
  end

  defp jac_mul(point, k) do
    # MSB-first double-and-add over the fixed 256-bit scalar: the accumulator
    # is doubled every iteration and the affine base point is added via the
    # fast mixed-addition path when the bit is set.
    do_jac_mul(point, k, 255, {1, 1, 0})
  end

  defp do_jac_mul(_point, _k, -1, acc), do: acc

  defp do_jac_mul(point, k, i, acc) do
    acc = jac_double(acc)

    acc =
      if Bitwise.band(Bitwise.bsr(k, i), 1) == 1,
        do: jac_add_mixed(acc, point),
        else: acc

    do_jac_mul(point, k, i - 1, acc)
  end

  # -- Scalar multiplication ---------------------------------------------------

  # Public entry point: returns affine point
  def mul(:infinity, _k), do: :infinity
  def mul(_p, 0), do: :infinity
  def mul(point, k) when k < 0, do: mul(neg(point), -k)

  def mul(point, k) do
    k_mod = rem(k, @n)
    if k_mod == 0, do: :infinity, else: jac_mul(point, k_mod) |> jac_to_affine()
  end

  # -- Encoding / Decoding ----------------------------------------------------

  def encode_public({x, y}) do
    <<0x04, x::256-big, y::256-big>>
  end

  def encode_signature(r, s), do: <<r::256-big, s::256-big>>

  def decode_signature(<<r::32-binary, s::32-binary>>) do
    {:binary.decode_unsigned(r, :big), :binary.decode_unsigned(s, :big)}
  end

  # -- Key generation ---------------------------------------------------------

  # Private keys must be in [1, n - 2] (GM/T 0003-2012). A key of n - 1 would
  # make (1 + d) ≡ 0 (mod n), which could never produce a valid signature.
  def generate_private_key do
    bytes = :crypto.strong_rand_bytes(32)
    k = :binary.decode_unsigned(bytes, :big)
    if k == 0, do: generate_private_key(), else: rem(k, @n - 2) + 1
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
    case mod_inv(1 + d, @n) do
      # 1 + d ≡ 0 (mod n) means d = n - 1, outside the valid private key
      # range. Reject it as an invalid key instead of looping forever on
      # s = 0 (every retry would produce s = 0 again).
      0 -> {:error, :invalid_key}
      inv -> do_sign_with_e(e, d, inv)
    end
  end

  defp do_sign_with_e(e, d, inv) do
    k = generate_k()
    {x1, _y1} = mul(generator(), k)
    r = scalar_add(e, x1)

    if r == 0 or r + k == @n do
      do_sign_with_e(e, d, inv)
    else
      s = scalar_mul(inv, scalar_sub(k, scalar_mul(r, d)))
      if s == 0, do: do_sign_with_e(e, d, inv), else: {:ok, encode_signature(r, s)}
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
end
