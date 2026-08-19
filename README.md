# Guomi

[![Hex.pm](https://img.shields.io/hexpm/v/guomi.svg)](https://hex.pm/packages/guomi)
[![Hex.pm](https://img.shields.io/hexpm/dt/guomi.svg)](https://hex.pm/packages/guomi)
[![Hex.pm](https://img.shields.io/hexpm/l/guomi.svg)](https://github.com/ZeroMarker/guomi/blob/main/LICENSE)
[![CI](https://github.com/ZeroMarker/guomi/actions/workflows/ci.yml/badge.svg)](https://github.com/ZeroMarker/guomi/actions/workflows/ci.yml)

国密算法纯 Elixir 实现（GM/T 0002-2012, GM/T 0003-2012, GM/T 0004-2012），无需外部依赖。

> SM2 标准接口已有公开向量和 OpenSSL 互操作测试，但尚未完成独立安全审查；旧兼容加密接口不得用于保护敏感数据。详见[兼容性与安全边界](#兼容性与安全边界)。

## 文档导航

- [库 API 快速入门](#使用)
- [命令行工具完整说明](cli.md)
- [SM2 标准兼容与迁移设计](sm2_migration.md)
- [安全策略与适用边界](SECURITY.md)
- [流式 API、证书与 SM9 范围](future_work.md)
- [版本变更记录](CHANGELOG.md)
- [开发路线图](todo.md)
- [发布维护指南](hex.pm.md)

## 支持状态

| 算法 | 状态 | 说明 |
|------|------|------|
| SM2  | ✅ 已实现 | 密钥对生成、签名、验签、加密、解密 |
| SM3  | ✅ 已实现 | 哈希、十六进制输出 |
| SM4  | ✅ 已实现 | ECB/CBC/CTR 模式，ECB/CBC 支持 `:pkcs7` 与 `:none` 填充 |

## 依赖

- Elixir 1.14+
- Erlang/OTP 24+

## 兼容性矩阵

所有算法均为纯 Elixir 实现，**无需运行时 OpenSSL 国密支持**。`supported?/0` 在所有受支持的 Erlang/OTP 版本上均返回 `true`。

| 能力 | 说明 |
|------|------|
| SM3 | 纯 Elixir 实现（GM/T 0004-2012 压缩函数），32 字节摘要 |
| SM4 ECB/CBC | 纯 Elixir 实现（GM/T 0002-2012 S-box 与密钥扩展），支持 `:pkcs7` 与 `:none` 填充 |
| SM4 CTR | 纯 Elixir 实现，16 字节初始计数器块按大端 128 位整数递增，不提供认证 |
| SM2 密钥/签名 | 标准接口计算 ZA，签名为 64 字节 raw `r || s`；另保留不计算 ZA 的旧兼容接口 |
| SM2 加密/解密 | 标准接口使用 `C1 || C3 || C2` 和 SM3 KDF；旧 `C1 || C2 || C3` 接口仅用于兼容 |

## API 约定

- SM3 哈希函数直接返回二进制摘要或小写十六进制字符串。
- SM2 与 SM4 操作返回 `{:ok, result}` 或 `{:error, reason}`，便于调用方显式处理错误。
- SM2 私钥固定为 32 字节，公钥固定为 65 字节未压缩点格式 `0x04 || x || y`。
- SM2 签名固定为 64 字节 raw `r || s` 格式。
- SM4 密钥、CBC IV 和 CTR 初始计数器块均固定为 16 字节。

可通过门面模块查询库暴露的算法：

```elixir
Guomi.algorithms()
#=> [:sm2, :sm3, :sm4]

Guomi.supported()
#=> %{sm2: true, sm3: true, sm4: true}
```

## 安装

### 从 Hex 安装

```elixir
def deps do
  [
    {:guomi, "~> 0.5.2"}
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

# 检查运行时支持（始终为 true）
Guomi.SM3.supported?()
#=> true
```

### SM4 加密

> 安全提示：ECB 模式只适合测试或兼容场景，不建议用于新数据加密。CBC 模式必须为每次加密使用不可预测且不复用的 16 字节 IV。CTR 模式只提供机密性，不提供认证；同一密钥下计数器块不得复用。

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

# CTR 模式（无填充，适合任意长度输入）
counter = <<0::128>>
{:ok, cipher} = Guomi.SM4.encrypt_ctr("Hello, Guomi!", key, counter)
{:ok, back} = Guomi.SM4.decrypt_ctr(cipher, key, counter)

# 检查运行时支持（始终为 true）
Guomi.SM4.supported?()
#=> true
```

### SM2 签名和加密

> 兼容性提示：当前 SM2 签名使用 SM3 预哈希和 raw `r || s` 签名格式，未暴露用户 ID/ZA 参数。SM2 加密使用本库内部格式，不应假定可与 OpenSSL 或其他 SM2 实现互通；由于长消息会重复 XOR 掩码，该接口仅用于兼容和测试，不得用于敏感数据或生产协议。

```elixir
# 生成密钥对
{:ok, private_key, public_key} = Guomi.SM2.generate_keypair()

# 签名
{:ok, signature} = Guomi.SM2.sign("message", private_key)

# 验签
{:ok, valid?} = Guomi.SM2.verify("message", signature, public_key)

# 加密
{:ok, ciphertext} = Guomi.SM2.encrypt("secret message", public_key)

# 解密
{:ok, plaintext} = Guomi.SM2.decrypt(ciphertext, private_key)

# 标准签名 API 要求显式 user ID，并计算 SM3(ZA || message)
user_id = "1234567812345678"
{:ok, standard_signature} = Guomi.SM2.sign_standard("message", private_key, user_id)
{:ok, true} =
  Guomi.SM2.verify_standard("message", standard_signature, public_key, user_id)

# 标准加密使用 C1 || C3 || C2 与可扩展 SM3 KDF（当前拒绝空消息）
{:ok, standard_ciphertext} = Guomi.SM2.encrypt_standard("secret message", public_key)
{:ok, "secret message"} = Guomi.SM2.decrypt_standard(standard_ciphertext, private_key)

# 检查运行时支持（始终为 true）
Guomi.SM2.supported?()
#=> true
```

### 常见错误

```elixir
Guomi.SM4.encrypt("data", "short key")
#=> {:error, :invalid_key_size}

Guomi.SM2.verify("message", <<0>>, <<0>>)
#=> {:error, :invalid_key}
```

SM2 可能返回 `:invalid_input`、`:invalid_key`、`:invalid_signature`、`:invalid_ciphertext` 或 `:decryption_failed`。SM4 可能返回 `:invalid_key_size`、`:invalid_iv_size`、`:invalid_block_size` 或 `:invalid_padding`。

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
#=> becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268

# SM4 加密，输出 hex 密文
echo "secret" | guomi sm4 --key 0123456789abcdef0123456789abcdef --hex

# SM4 解密，读取 hex 密文并输出明文
guomi sm4 --decrypt --hex --key 0123456789abcdef0123456789abcdef < ciphertext.hex

# 显式控制 SM4 hex 输入/输出
echo -n "736563726574" | guomi sm4 --input-hex --output-hex --key 0123456789abcdef0123456789abcdef

# SM2 生成密钥对
guomi sm2 --generate

# SM2 签名
echo "message" | guomi sm2 --sign --private-key <hex-key>

# SM2 验签
guomi sm2 --verify --public-key <hex-key> --signature <hex-sig> --file message.txt
```

### 完整文档

参阅 [CLI 完整说明](cli.md)，或运行 `guomi help`、`guomi <command> --help` 查看可用选项。

## 开发

### 安装依赖

```bash
mix deps.get
```

### 运行测试

```bash
mix test
```

### 完整质量检查

```bash
mix format --check-formatted
mix compile --warnings-as-errors
mix test
mix credo --strict
MIX_ENV=test mix coveralls.json
```

Windows PowerShell 中可将最后一条命令写为 `$env:MIX_ENV="test"; mix coveralls.json`。

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

### 运行微基准

```bash
mix run bench/bench.exs
```

该脚本用于本机回归比较，不代表跨硬件的正式性能基线。记录结果时应同时注明硬件、操作系统、OTP/Elixir 版本和运行参数。

## 许可证

MIT License. See [LICENSE](LICENSE) for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed list of changes.

### Recent Versions

#### [0.5.2] - 2026-08-19
- Added standards-compatible SM2 ZA-aware signing and C1/C3/C2 encryption APIs
- Removed modulo bias from SM2 private-key and signature nonce generation
- Improved legacy SM2 ciphertext error reporting for off-curve ephemeral points

#### [0.5.1] - 2026-05-31
- Added SM4 CTR APIs for arbitrary-length data without padding
- Tightened SM2 invalid-input error handling
- Fixed SM2 signature scalar modular inverse and sign/verify timeout

#### [0.5.0] - 2026-05-16
- Pure Elixir SM2/SM3/SM4 implementations — no runtime OpenSSL dependency
- All `supported?/0` now return `true` unconditionally
- Expanded test coverage with block boundary and edge case tests

#### [0.4.2] - 2026-05-16
- Fixed Credo strict warnings in CLI, SM2, SM4, and OpenSSL compatibility tests
- Normalized source file line endings for Credo consistency checks

#### [0.4.1] - 2026-05-16
- Made SM3/SM4 tests runtime-aware when CI OpenSSL lacks Guomi algorithms
- Added friendly SM3 CLI unsupported-runtime errors

#### [0.4.0] - 2026-05-16
- Unified Hex workflow for CI checks and release publishing
- Improved CLI validation and explicit SM4 hex input/output flags
- Added ExUnit CLI and OpenSSL compatibility tests
- Documented SM2 compatibility limits and SM4 security caveats

#### [0.3.0] - 2026-04-05
- CLI tool with commands for SM2, SM3, and SM4 operations
- Version and help commands for CLI

#### [0.2.0] - 2026-04-01
- SM2 encryption and decryption functionality

#### [0.1.0] - 2026-03-28
- Initial release
- SM2/SM3/SM4 implementations

[0.5.2]: https://github.com/ZeroMarker/guomi/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/ZeroMarker/guomi/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/ZeroMarker/guomi/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/ZeroMarker/guomi/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/ZeroMarker/guomi/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ZeroMarker/guomi/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ZeroMarker/guomi/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ZeroMarker/guomi/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ZeroMarker/guomi/releases/tag/v0.1.0

## 兼容性与安全边界

- **SM2 签名**：`sign_standard/3`、`verify_standard/4` 提供显式用户 ID/ZA 的 raw `r || s` 接口；旧 `sign/2`、`verify/3` 只对消息做 SM3 预哈希，仅用于兼容。
- **SM2 加密**：`encrypt_standard/2`、`decrypt_standard/2` 使用 `C1 || C3 || C2` 与可扩展 SM3 KDF，但仍未经独立安全审查。旧 `encrypt/2`、`decrypt/2` 采用内部 `C1 || C2 || C3` 格式并对超过 32 字节的消息重复 XOR 掩码，仅用于兼容和测试，不得用于保护敏感数据或生产协议。
- **ECB**：会泄露明文模式，不要用于新系统中的敏感数据保护。
- **CBC**：每次加密必须使用不可预测且不复用的 16 字节 IV；当前接口不提供认证。
- **CTR**：同一密钥下不得复用初始计数器块；当前接口只提供机密性，不提供认证。
- **性能**：核心算法为纯 Elixir 实现。部署前请在目标硬件和实际消息大小上自行基准测试。

## FAQ

### Q: `Guomi.SM2.supported?()` 为什么永远返回 `true`？

A: 所有算法均为纯 Elixir 实现，不依赖运行时 OpenSSL 的国密算法支持。该函数在所有支持的 Erlang/OTP 版本上均返回 `true`。

### Q: 如何在生产环境使用？

A: 确保部署环境满足 Erlang/OTP 24+ 与 Elixir 1.14+，并根据业务场景处理密钥管理、随机数、消息认证、密文格式兼容性和性能评估。该库不替代完整的密钥管理或加密协议设计。

### Q: 性能如何？

A: 纯 Elixir 实现的性能高度依赖 OTP 版本、硬件、消息大小和并发模型。可运行 `mix run bench/bench.exs` 做本机回归比较；仓库当前不维护跨硬件的正式性能基线，部署前仍应在目标环境中测量。

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

- [Erlang/OTP](https://www.erlang.org/) - 基础加密能力与随机数生成

## 相关链接

- [Hex 包](https://hex.pm/packages/guomi)
- [文档](https://hexdocs.pm/guomi)
- [问题追踪](https://github.com/ZeroMarker/guomi/issues)

## Roadmap

P0/P1 实现与自动化验证已经完成。当前剩余工作是独立安全审查和 SM2 曲线热点的进一步性能分析，详情及历史验收记录见 [todo.md](todo.md)。
