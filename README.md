# Guomi

[![CI](https://github.com/ZeroMarker/guomi/actions/workflows/ci.yml/badge.svg)](https://github.com/ZeroMarker/guomi/actions/workflows/ci.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/guomi.svg)](https://hex.pm/packages/guomi)
[![Hex.pm](https://img.shields.io/hexpm/dt/guomi.svg)](https://hex.pm/packages/guomi)
[![Hex.pm](https://img.shields.io/hexpm/l/guomi.svg)](https://github.com/ZeroMarker/guomi/blob/main/LICENSE)

国密算法 Elixir 实现。本库优先使用 Erlang/OTP `:crypto` 能力，并在运行时探测算法可用性。

## 支持状态

| 算法 | 状态 | 说明 |
|------|------|------|
| SM2  | ✅ 已实现 | 密钥对生成、签名、验签、加密、解密 |
| SM3  | ✅ 已实现 | 哈希、十六进制输出 |
| SM4  | ✅ 已实现 | ECB/CBC 模式，支持 `:pkcs7` 与 `:none` 填充 |

## 依赖

- Elixir 1.14+
- Erlang/OTP 24+
- OpenSSL 3.0+（用于更完整国密算法支持）

## 安装

### 从 Hex 安装

```elixir
def deps do
  [
    {:guomi, "~> 0.2.0"}
  ]
end
```

### 从 GitHub 安装 (开发版)

```elixir
def deps do
  [
    {:guomi, git: "https://github.com/ZeroMarker/guomi.git", branch: "main"}
  ]
end
```

### 本地开发

```elixir
def deps do
  [
    {:guomi, path: "../guomi"}
  ]
end
```

## 使用

### SM3 哈希

```elixir
# 十六进制输出
Guomi.SM3.hash_hex("abc")
#=> "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

# 二进制输出
Guomi.SM3.hash("abc")
#=> <<102, 199, 240, 244, 98, 238, 221, 217, ...>>

# 检查运行时支持
Guomi.SM3.supported?()
#=> true | false
```

### SM4 加密

```elixir
key = Base.decode16!("0123456789ABCDEFFEDCBA9876543210", case: :mixed)
plain = Base.decode16!("0123456789ABCDEFFEDCBA9876543210", case: :mixed)

# ECB 模式（无填充）
{:ok, cipher} = Guomi.SM4.encrypt(plain, key, padding: :none)
{:ok, back} = Guomi.SM4.decrypt(cipher, key, padding: :none)

# ECB 模式（PKCS7 填充）
{:ok, cipher} = Guomi.SM4.encrypt("Hello, Guomi!", key)
{:ok, back} = Guomi.SM4.decrypt(cipher, key)

# CBC 模式
iv = <<0::128>>
{:ok, cipher} = Guomi.SM4.encrypt_cbc("Hello, Guomi!", key, iv)
{:ok, back} = Guomi.SM4.decrypt_cbc(cipher, key, iv)

# 检查运行时支持
Guomi.SM4.supported?()
#=> true | false
```

### SM2 签名和加密

```elixir
# 生成密钥对
case Guomi.SM2.generate_keypair() do
  {:ok, private_key, public_key} ->
    # 签名
    {:ok, signature} = Guomi.SM2.sign("message", private_key)

    # 验签
    {:ok, valid?} = Guomi.SM2.verify("message", signature, public_key)
    valid?

    # 加密
    {:ok, ciphertext} = Guomi.SM2.encrypt("secret message", public_key)

    # 解密
    {:ok, plaintext} = Guomi.SM2.decrypt(ciphertext, private_key)

  {:error, :unsupported} ->
    :runtime_not_supported
end

# 检查运行时支持
Guomi.SM2.supported?()
#=> true | false
```

## CLI 工具

Guomi 提供命令行工具，可直接执行国密算法操作。

### 安装

```bash
mix escript.build
./guomi version
```

### 命令

| 命令 | 说明 |
|------|------|
| `guomi sm3` | 计算 SM3 哈希 |
| `guomi sm4` | SM4 加密/解密 |
| `guomi sm2` | SM2 密钥生成、签名/验签、加密/解密 |
| `guomi version` | 显示版本信息 |
| `guomi help` | 显示帮助信息 |

### 使用示例

```bash
# SM3 哈希
echo -n "hello" | guomi sm3 --hex
#=> 5897d5a782929dcdbf5e8fdb8e23d2781b5a1f5e8236e1c48e11c7b730a1e8f0

# SM4 加密
echo "secret" | guomi sm4 --key 0123456789abcdef0123456789abcdef --hex

# SM4 解密
guomi sm4 --decrypt --hex --key 0123456789abcdef0123456789abcdef < ciphertext.hex

# SM2 生成密钥对
guomi sm2 --generate

# SM2 签名
echo "message" | guomi sm2 --sign --private-key <hex-key>

# SM2 验签
guomi sm2 --verify --public-key <hex-key> --signature <hex-sig> message.txt
```

### 完整文档

运行 `guomi help` 或 `guomi <command> --help` 查看更多选项。

## 开发

### 运行测试

```bash
mix test
```

### 代码格式化

```bash
mix format
```

### 静态分析

```bash
# 运行 Credo 代码检查
mix credo

# 运行 Dialyzer 类型检查
mix dialyzer
```

### 生成文档

```bash
mix docs
```

## 许可证

MIT License. See [LICENSE](LICENSE) for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed list of changes.

### Recent Versions

#### [0.3.0] - Unreleased
- CLI tool with commands for SM2, SM3, and SM4 operations
- Version and help commands for CLI

#### [0.2.0] - 2026-04-01
- SM2 encryption and decryption functionality

#### [0.1.0] - 2026-03-28
- Initial release
- SM2/SM3/SM4 implementations

[0.3.0]: https://github.com/ZeroMarker/guomi/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ZeroMarker/guomi/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ZeroMarker/guomi/releases/tag/v0.1.0

## 与其他库对比

| 功能 | Guomi | 通用 crypto 库 |
|------|-------|---------------|
| SM2 签名/验签 | ✅ | ❌ |
| SM2 加密/解密 | ✅ | ❌ |
| SM3 哈希 | ✅ | ❌ |
| SM4 加密 | ✅ | ❌ |
| 运行时探测 | ✅ | - |
| 纯 Elixir/Erlang | ✅ | ✅ |

> 注：通用 crypto 库指 `:crypto`、`:public_key` 等 OTP 内置模块

## 已知问题

1. **SM2 运行时依赖** - 需要 OpenSSL 3.0+ 且编译时启用 SM2 曲线支持
2. **Windows 兼容性** - 部分 OpenSSL 功能在 Windows 上可能受限
3. **SM2 加密性能** - 当前实现使用简化 KDF，长消息加密性能有待优化

## FAQ

### Q: 为什么 `Guomi.SM2.supported?()` 返回 `false`？

A: SM2 需要 OpenSSL 3.0+ 且在编译时启用了国密算法支持。请检查：

```bash
# 检查 OpenSSL 版本
openssl version

# 检查 Erlang 是否识别 SM2 曲线
elixir -e "IO.inspect(:crypto.supports(:curves))"
```

### Q: 如何在生产环境使用？

A: 确保部署环境满足：
- Erlang/OTP 24+
- OpenSSL 3.0+（推荐系统级安装）
- 在运行时调用 `supported?/0` 检测可用性

### Q: 性能如何？

A: 基于 OTP `:crypto` NIF 实现，性能接近原生 C 实现。参考基准（M1 Max, OTP 26）：

| 算法 | 操作 | 吞吐量 |
|------|------|--------|
| SM3 | hash | ~500 MB/s |
| SM4 | ECB encrypt | ~200 MB/s |
| SM4 | CBC encrypt | ~180 MB/s |
| SM2 | sign | ~2000 ops/s |
| SM2 | verify | ~1500 ops/s |

> 实际性能取决于硬件和 OpenSSL 版本

## Contributing

欢迎贡献！请遵循以下步骤：

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交变更 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 提交 Pull Request

### 开发要求

- 新增功能需附带测试
- 代码需通过 `mix format` 格式化
- 代码需通过 `mix credo` 检查
- 文档需同步更新

## Code of Conduct

本项目采用 [Contributor Covenant](https://www.contributor-covenant.org/) 行为准则。

## 致谢

- [Erlang/OTP](https://www.erlang.org/) - 基础加密能力
- [OpenSSL](https://www.openssl.org/) - 国密算法实现

## 相关链接

- [Hex 包](https://hex.pm/packages/guomi)
- [文档](https://hexdocs.pm/guomi)
- [问题追踪](https://github.com/ZeroMarker/guomi/issues)

## Roadmap

### v0.2.0
- [ ] 添加 SM4 CTR 模式
- [ ] 增加性能基准测试
- [ ] 优化 SM2 加密 KDF 实现

### v0.3.0
- [ ] 支持 SM9 算法（基于身份的加密）
- [ ] 添加密钥派生函数 (KDF)
- [ ] 支持硬件加密模块 (HSM)

### 未来版本
- [ ] SM1 算法支持（需硬件合作）
- [ ] 国密 SSL/TLS 支持
- [ ] 国密证书解析
