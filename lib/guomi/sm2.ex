defmodule Guomi.SM2 do
  @moduledoc """
  SM2 椭圆曲线公钥密码算法实现。

  SM2 是中国国家密码管理局发布的椭圆曲线公钥密码算法标准（GM/T 0003-2012），
  基于 GF(p) 上的 256 位椭圆曲线。

  ## 使用示例

      iex> {:ok, priv, pub} = Guomi.SM2.generate_keypair()
      iex> {:ok, signature} = Guomi.SM2.sign(message, priv)
      iex> {:ok, true} = Guomi.SM2.verify(message, signature, pub)

  """

  alias Guomi.SM3

  # SM2 椭圆曲线参数 (GF(p): y^2 = x^3 + ax + b)
  # p = 2^256 - 2^224 - 2^96 + 2^64 - 1
  @p 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
  # a = -3
  @a 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
  # b
  @b 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
  # n (阶)
  @n 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
  # G (基点)
  @gx 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
  @gy 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

  @doc """
  生成 SM2 密钥对。

  ## 返回

    - `{:ok, private_key, public_key}` - 生成成功
    - private_key: 32 字节私钥
    - public_key: 65 字节公钥 (04 || x || y)

  ## 示例

      iex> {:ok, priv, pub} = Guomi.SM2.generate_keypair()

  """
  def generate_keypair do
    # 生成随机私钥
    private_key = :crypto.strong_rand_bytes(32)
    <<d::unsigned-integer-size(256)>> = private_key

    # 确保私钥在 [1, n-1] 范围内
    d = rem(d, @n - 1) + 1
    private_key = <<d::unsigned-integer-size(256)>>

    # 计算公钥 Q = d * G
    {qx, qy} = point_multiply(d, {@gx, @gy})

    public_key = <<0x04, qx::unsigned-integer-size(256), qy::unsigned-integer-size(256)>>

    {:ok, private_key, public_key}
  end

  @doc """
  SM2 签名。

  ## 参数

    - message: 待签名的消息
    - private_key: 私钥
    - user_id: 用户 ID (可选，默认使用 "1234567812345678")

  ## 返回

    - `{:ok, signature}` - 签名成功，返回 64 字节签名 (r || s)
    - `{:error, reason}` - 签名失败

  """
  def sign(message, private_key, user_id \\ "1234567812345678")
      when is_binary(message) and is_binary(private_key) do
    <<d::unsigned-integer-size(256)>> = private_key

    # 计算 Z_A
    <<qx::unsigned-integer-size(256), qy::unsigned-integer-size(256)>> =
      public_key_from_private(private_key)

    za = calculate_z(user_id, qx, qy)

    # 计算 e = Hash(Z_A || M)
    e = message |> (fn m -> za <> m end).() |> SM3.hash() |> :binary.decode_unsigned()
    e = rem(e, @n)

    # 签名生成
    sign_loop(e, d)
  end

  defp sign_loop(e, d) do
    # 生成随机数 k
    <<k::unsigned-integer-size(256)>> = :crypto.strong_rand_bytes(32)
    k = rem(k, @n - 1) + 1

    # 计算 (x1, y1) = k * G
    {x1, _y1} = point_multiply(k, {@gx, @gy})

    # r = (e + x1) mod n
    r = rem(e + x1, @n)

    if r == 0 or r + k == @n do
      sign_loop(e, d)
    else
      # s = ((1 + d)^-1 * (k - r * d)) mod n
      d_plus_1_inv = mod_inverse(rem(1 + d, @n), @n)
      # 正确处理负数：(k - r * d) mod n
      kd = rem(r * d, @n)
      k_minus_kd = if k >= kd, do: k - kd, else: @n + k - kd
      s = rem(d_plus_1_inv * k_minus_kd, @n)

      if s == 0 do
        sign_loop(e, d)
      else
        signature = <<r::unsigned-integer-size(256), s::unsigned-integer-size(256)>>
        {:ok, signature}
      end
    end
  end

  @doc """
  SM2 验签。

  ## 参数

    - message: 待验证的消息
    - signature: 签名 (64 字节)
    - public_key: 公钥 (65 字节，04 || x || y)
    - user_id: 用户 ID (可选)

  ## 返回

    - `{:ok, true}` - 验签成功
    - `{:ok, false}` - 验签失败
    - `{:error, reason}` - 验证失败

  """
  def verify(message, signature, public_key, user_id \\ "1234567812345678")
      when is_binary(message) and is_binary(signature) and is_binary(public_key) do
    <<r::unsigned-integer-size(256), s::unsigned-integer-size(256)>> = signature
    <<0x04, qx::unsigned-integer-size(256), qy::unsigned-integer-size(256)>> = public_key

    # 验证 r, s 范围
    cond do
      r < 1 or r >= @n ->
        {:ok, false}

      s < 1 or s >= @n ->
        {:ok, false}

      true ->
        # 计算 Z_A
        za = calculate_z(user_id, qx, qy)

        # 计算 e = Hash(Z_A || M)
        e = message |> (fn m -> za <> m end).() |> SM3.hash() |> :binary.decode_unsigned()
        e = rem(e, @n)

        # t = (r + s) mod n
        t = rem(r + s, @n)

        if t == 0 do
          {:ok, false}
        else
          # (x1, y1) = s * G + t * Q
          sg = point_multiply(s, {@gx, @gy})
          tq = point_multiply(t, {qx, qy})
          {x1, _y1} = point_add(sg, tq)

          # R = (e + x1) mod n
          r_check = rem(e + x1, @n)

          {:ok, r_check == r}
        end
    end
  end

  @doc """
  SM2 加密。

  ## 参数

    - plaintext: 明文
    - public_key: 公钥

  ## 返回

    - `{:ok, ciphertext}` - 加密成功
    - `{:error, reason}` - 加密失败

  """
  def encrypt(plaintext, public_key)
      when is_binary(plaintext) and is_binary(public_key) do
    <<0x04, qx::unsigned-integer-size(256), qy::unsigned-integer-size(256)>> = public_key

    # 生成随机数 k
    <<k::unsigned-integer-size(256)>> = :crypto.strong_rand_bytes(32)
    k = rem(k, @n - 1) + 1

    # C1 = k * G = (x1, y1)
    {x1, y1} = point_multiply(k, {@gx, @gy})
    c1 = <<0x04, x1::unsigned-integer-size(256), y1::unsigned-integer-size(256)>>

    # (x2, y2) = k * Q
    {x2, y2} = point_multiply(k, {qx, qy})

    # 生成密钥流
    t = kdf(<<x2::unsigned-integer-size(256), y2::unsigned-integer-size(256)>>, byte_size(plaintext))

    if all_zeros?(t) do
      encrypt(plaintext, public_key)
    else
      # C2 = M XOR t
      c2 = xor_bytes(plaintext, t)

      # C3 = Hash(x2 || M || y2)
      c3 = SM3.hash(<<x2::unsigned-integer-size(256)>> <> plaintext <> <<y2::unsigned-integer-size(256)>>)

      ciphertext = c1 <> c3 <> c2
      {:ok, ciphertext}
    end
  end

  @doc """
  SM2 解密。

  ## 参数

    - ciphertext: 密文
    - private_key: 私钥

  ## 返回

    - `{:ok, plaintext}` - 解密成功
    - `{:error, reason}` - 解密失败

  """
  def decrypt(ciphertext, private_key)
      when is_binary(ciphertext) and is_binary(private_key) do
    if byte_size(ciphertext) < 97 do
      {:error, "密文长度无效"}
    else
      <<c1::binary-size(65), c3::binary-size(32), c2::binary>> = ciphertext

      <<0x04, x1::unsigned-integer-size(256), y1::unsigned-integer-size(256)>> = c1
      <<d::unsigned-integer-size(256)>> = private_key

      # (x2, y2) = d * C1
      {x2, y2} = point_multiply(d, {x1, y1})

      # 生成密钥流
      t = kdf(<<x2::unsigned-integer-size(256), y2::unsigned-integer-size(256)>>, byte_size(c2))

      if all_zeros?(t) do
        {:error, "密钥流全零"}
      else
        # M = C2 XOR t
        plaintext = xor_bytes(c2, t)

        # 验证 C3
        expected_c3 = SM3.hash(<<x2::unsigned-integer-size(256)>> <> plaintext <> <<y2::unsigned-integer-size(256)>>)

        if expected_c3 == c3 do
          {:ok, plaintext}
        else
          {:error, "校验失败"}
        end
      end
    end
  end

  # 计算 Z_A = Hash(ENTL || ID || a || b || Gx || Gy || Px || Py)
  defp calculate_z(user_id, qx, qy) do
    entl = byte_size(user_id) * 8
    entl_bin = <<entl::size(16)>>

    data =
      entl_bin <>
      user_id <>
      <<@a::unsigned-integer-size(256)>> <>
      <<@b::unsigned-integer-size(256)>> <>
      <<@gx::unsigned-integer-size(256)>> <>
      <<@gy::unsigned-integer-size(256)>> <>
      <<qx::unsigned-integer-size(256)>> <>
      <<qy::unsigned-integer-size(256)>>

    SM3.hash(data)
  end

  # 从私钥计算公钥
  defp public_key_from_private(private_key) do
    <<d::unsigned-integer-size(256)>> = private_key
    {qx, qy} = point_multiply(d, {@gx, @gy})
    <<qx::unsigned-integer-size(256), qy::unsigned-integer-size(256)>>
  end

  # 椭圆曲线点乘 k * P
  defp point_multiply(k, {_px, _py}) when k == 0, do: :point_at_infinity
  defp point_multiply(k, {px, py}) do
    point_multiply_loop(k, {px, py}, :point_at_infinity, {px, py})
  end

  defp point_multiply_loop(0, _, acc, _), do: acc
  defp point_multiply_loop(k, base, acc, addend) do
    if rem(k, 2) == 1 do
      new_acc = point_add(acc, addend)
      point_multiply_loop(div(k, 2), base, new_acc, point_double(addend))
    else
      point_multiply_loop(div(k, 2), base, acc, point_double(addend))
    end
  end

  # 点加倍 2P
  defp point_double(:point_at_infinity), do: :point_at_infinity
  defp point_double({x, y}) do
    if y == 0 do
      :point_at_infinity
    else
      # lambda = (3x^2 + a) / (2y) mod p
      numerator = rem(3 * x * x + @a, @p)
      denominator = rem(2 * y, @p)
      lambda = rem(numerator * mod_inverse(denominator, @p), @p)

      # x3 = lambda^2 - 2x mod p
      x3 = rem(lambda * lambda - 2 * x, @p)
      x3 = if x3 < 0, do: x3 + @p, else: x3

      # y3 = lambda(x - x3) - y mod p
      y3 = rem(lambda * (x - x3) - y, @p)
      y3 = if y3 < 0, do: y3 + @p, else: y3

      {x3, y3}
    end
  end

  # 点加 P + Q
  defp point_add(:point_at_infinity, q), do: q
  defp point_add(p, :point_at_infinity), do: p
  defp point_add({x1, y1}, {x2, y2}) when x1 == x2 and y1 == y2 do
    point_double({x1, y1})
  end
  defp point_add({x1, y1}, {x2, y2}) when x1 == x2 and y1 != y2 do
    :point_at_infinity
  end
  defp point_add({x1, y1}, {x2, y2}) do
    # lambda = (y2 - y1) / (x2 - x1) mod p
    numerator = rem(y2 - y1, @p)
    numerator = if numerator < 0, do: numerator + @p, else: numerator

    denominator = rem(x2 - x1, @p)
    denominator = if denominator < 0, do: denominator + @p, else: denominator

    lambda = rem(numerator * mod_inverse(denominator, @p), @p)

    # x3 = lambda^2 - x1 - x2 mod p
    x3 = rem(lambda * lambda - x1 - x2, @p)
    x3 = if x3 < 0, do: x3 + @p, else: x3

    # y3 = lambda(x1 - x3) - y1 mod p
    y3 = rem(lambda * (x1 - x3) - y1, @p)
    y3 = if y3 < 0, do: y3 + @p, else: y3

    {x3, y3}
  end

  # 模逆运算
  defp mod_inverse(a, m) do
    {g, x, _} = extended_gcd(a, m)
    if g != 1 do
      raise "模逆不存在"
    else
      rem(x, m) + m
    end
  end

  defp extended_gcd(a, b) when a == 0, do: {b, 0, 1}
  defp extended_gcd(a, b) do
    {g, x, y} = extended_gcd(rem(b, a), a)
    {g, y - div(b, a) * x, x}
  end

  # KDF 密钥派生函数
  defp kdf(z, len) do
    kdf_loop(z, len, <<>>, 1)
  end

  defp kdf_loop(_z, len, acc, _ct) when byte_size(acc) >= len do
    :binary.part(acc, 0, len)
  end

  defp kdf_loop(z, len, acc, ct) do
    <<ct_bin::unsigned-integer-size(32)>> = <<ct::unsigned-integer-size(32)>>
    hash = SM3.hash(z <> <<ct_bin::unsigned-integer-size(32)>>)
    kdf_loop(z, len, acc <> hash, ct + 1)
  end

  defp all_zeros?(data) do
    data |> :binary.bin_to_list() |> Enum.all?(&(&1 == 0))
  end

  defp xor_bytes(a, b) do
    a |> :binary.bin_to_list() |> Enum.zip(b |> :binary.bin_to_list())
    |> Enum.map(fn {x, y} -> Bitwise.bxor(x, y) end)
    |> :binary.list_to_bin()
  end
end
