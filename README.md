# Guomi

国密算法 Elixir 实现。本库使用 Erlang crypto 模块实现中国国家密码管理局发布的密码算法标准。

## 支持的算法

- **SM2** - 椭圆曲线公钥密码算法（GM/T 0003-2012）
  - 密钥对生成
  - 数字签名和验签
  - 公钥加密和解密

- **SM3** - 密码杂凑算法（GM/T 0004-2012）
  - 256 位哈希值输出

- **SM4** - 分组密码算法（GM/T 0002-2012）
  - 128 位分组长度
  - 128 位密钥长度
  - ECB 和 CBC 模式

## 依赖

本库依赖 Erlang/OTP 24+ 和 OpenSSL 3.0+（提供国密算法支持）。

## 安装

```elixir
def deps do
  [
    {:guomi, "~> 0.1.0"}
  ]
end
```

## 使用示例

### SM3 哈希

```elixir
# 二进制哈希
Guomi.SM3.hash("hello")
# => <<0xbe, 0xcb, 0xbf, 0xaa, ...>>

# 十六进制字符串
Guomi.SM3.hash_hex("hello")
# => "becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268"
```

### SM4 加密解密

```elixir
# ECB 模式
key = :crypto.strong_rand_bytes(16)
plaintext = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>

# 加密
{:ok, ciphertext} = Guomi.SM4.encrypt(plaintext, key)

# 解密
{:ok, decrypted} = Guomi.SM4.decrypt(ciphertext, key)

# CBC 模式
iv = :crypto.strong_rand_bytes(16)
{:ok, ciphertext} = Guomi.SM4.encrypt_cbc(plaintext, key, iv)
{:ok, decrypted} = Guomi.SM4.decrypt_cbc(ciphertext, key, iv)
```

### SM2 签名验签

```elixir
# 生成密钥对
{:ok, private_key, public_key} = Guomi.SM2.generate_keypair()

# 签名
{:ok, signature} = Guomi.SM2.sign("message", private_key)

# 验签
{:ok, valid?} = Guomi.SM2.verify("message", signature, public_key)
```

### SM2 加密解密

```elixir
# 加密
{:ok, ciphertext} = Guomi.SM2.encrypt("secret", public_key)

# 解密
{:ok, plaintext} = Guomi.SM2.decrypt(ciphertext, private_key)
```

## 运行测试

```bash
mix test
```

## 生成文档

```bash
mix docs
```

## 注意事项

- SM3 和 SM4 使用 Erlang crypto 模块（需要 OpenSSL 3.0+）
- SM2 为纯 Elixir 实现，性能可能不如 NIF 实现
- 生产环境建议使用经过充分测试的密码学库

## 许可证

MIT License
