# Guomi

国密算法 Elixir 实现。本库优先使用 Erlang/OTP `:crypto` 能力，并在运行时探测算法可用性。

## 支持状态

- `SM3`：已实现（哈希、十六进制输出）
- `SM4`：已实现（ECB/CBC，支持 `:pkcs7` 与 `:none` 填充）
- `SM2`：已实现密钥对、签名、验签（依赖运行时是否支持 `:sm2` 曲线）
- `SM2` 加解密：当前返回 `{:error, :unsupported}`（OTP/OpenSSL 在不同环境支持差异较大）

## 依赖

- Elixir 1.14+
- Erlang/OTP 24+
- OpenSSL 3.0+（用于更完整国密算法支持）

## 安装

```elixir
def deps do
  [
    {:guomi, path: "../guomi"}
  ]
end
```

## 使用

```elixir
Guomi.SM3.hash_hex("abc")
#=> "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
```

```elixir
key = Base.decode16!("0123456789ABCDEFFEDCBA9876543210", case: :mixed)
plain = Base.decode16!("0123456789ABCDEFFEDCBA9876543210", case: :mixed)

{:ok, cipher} = Guomi.SM4.encrypt(plain, key, padding: :none)
{:ok, back} = Guomi.SM4.decrypt(cipher, key, padding: :none)
```

```elixir
case Guomi.SM2.generate_keypair() do
  {:ok, sk, pk} ->
    {:ok, sig} = Guomi.SM2.sign("message", sk)
    {:ok, valid?} = Guomi.SM2.verify("message", sig, pk)
    valid?

  {:error, :unsupported} ->
    :runtime_not_supported
end
```

## 测试

```bash
mix test
```
