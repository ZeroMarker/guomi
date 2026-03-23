# 项目分析报告：Guomi

## 📌 项目概述

**Guomi** 是一个 Elixir 语言实现的**国密算法库**，基于 Erlang/OTP `:crypto` 模块能力构建。

| 属性 | 值 |
|------|------|
| **项目名** | guomi |
| **版本** | 0.1.0 |
| **语言** | Elixir (~> 1.14) |
| **许可证** | MIT |
| **依赖** | 仅 `ex_doc`（开发文档）|

---

## 📁 项目结构

```
guomi/
├── lib/
│   ├── guomi.ex      # 主模块（外观模式，当前为空壳）
│   ├── sm2.ex        # SM2 非对称加密算法（签名/验签）
│   ├── sm3.ex        # SM3 哈希算法
│   └── sm4.ex        # SM4 对称加密算法（ECB/CBC模式）
├── test/
│   ├── sm2_test.exs  # SM2 测试（19个测试用例）
│   ├── sm3_test.exs  # SM3 测试（10个测试用例）
│   ├── sm4_test.exs  # SM4 测试（19个测试用例）
│   └── test_helper.exs
├── mix.exs           # 项目配置
└── README.md         # 中文文档
```

---

## 🔐 算法实现详情

### 1. SM3 - 哈希算法 (`lib/sm3.ex`)

| 功能 | 状态 | 说明 |
|------|------|------|
| `hash/1` | ✅ | 返回 32 字节二进制哈希 |
| `hash_hex/1` | ✅ | 返回 64 字符小写十六进制字符串 |
| `supported?/0` | ✅ | 运行时检测 SM3 可用性 |

**特点**：
- 支持 `binary()` 和 `iodata()` 输入
- 完全依赖 Erlang `:crypto.hash(:sm3, data)`

---

### 2. SM4 - 对称加密 (`lib/sm4.ex`)

| 功能 | 状态 | 说明 |
|------|------|------|
| ECB 模式 | ✅ | `encrypt/3`, `decrypt/3` |
| CBC 模式 | ✅ | `encrypt_cbc/4`, `decrypt_cbc/4` |
| PKCS7 填充 | ✅ | 默认填充方式 |
| 无填充 | ✅ | `padding: :none` |
| `supported?/0` | ✅ | 检测 SM4 可用性 |

**技术规格**：
- 密钥长度：16 字节（128位）
- 块大小：16 字节（128位）
- IV 长度：16 字节（CBC模式）

---

### 3. SM2 - 非对称加密 (`lib/sm2.ex`)

| 功能 | 状态 | 说明 |
|------|------|------|
| 密钥对生成 | ✅ | `generate_keypair/0` |
| 签名 | ✅ | `sign/2` |
| 验签 | ✅ | `verify/3` |
| 加密 | ❌ | 返回 `{:error, :unsupported}` |
| 解密 | ❌ | 返回 `{:error, :unsupported}` |
| `supported?/0` | ✅ | 检测 SM2 曲线和 SM3 支持 |

**技术规格**：
- 曲线：`:sm2`
- 私钥长度：32 字节
- 公钥长度：65 字节（未压缩格式，首字节 0x04）
- 签名长度：64 字节

---

## ✅ 测试覆盖

| 模块 | 测试数 | 覆盖率 |
|------|--------|--------|
| SM2 | 19 个 | 签名验签、边界条件、错误处理 |
| SM3 | 10 个 | 标准向量、边界条件、中文字符 |
| SM4 | 19 个 | ECB/CBC 模式、填充、大数据量 |

**测试特点**：
- 使用 `async: true` 并行执行
- 对不支持的环境优雅降级（`{:error, :unsupported}`）
- 包含官方标准测试向量

---

## 🏗️ 架构设计

```
┌─────────────────────────────────────────┐
│           Guomi (外观模块)              │
├─────────────┬─────────────┬─────────────┤
│   SM2       │    SM3      │    SM4      │
│  非对称加密  │   哈希算法   │  对称加密   │
├─────────────┴─────────────┴─────────────┤
│       Erlang/OTP :crypto 模块           │
├─────────────────────────────────────────┤
│         OpenSSL 3.0+ (底层)             │
└─────────────────────────────────────────┘
```

---

## ⚠️ 注意事项

1. **运行时依赖**：算法可用性取决于 Erlang/OTP 和 OpenSSL 版本
   - 推荐：OTP 24+ 和 OpenSSL 3.0+

2. **SM2 加密限制**：当前实现仅支持签名验签，加解密功能未实现

3. **错误处理**：所有 API 使用 `{:ok, result} | {:error, reason}` 元组返回格式

---

## 🚀 使用示例

```elixir
# SM3 哈希
Guomi.SM3.hash_hex("abc")
#=> "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

# SM4 加密
key = Base.decode16!("0123456789ABCDEFFEDCBA9876543210", case: :mixed)
{:ok, cipher} = Guomi.SM4.encrypt("secret data", key)
{:ok, plain} = Guomi.SM4.decrypt(cipher, key)

# SM2 签名
{:ok, sk, pk} = Guomi.SM2.generate_keypair()
{:ok, sig} = Guomi.SM2.sign("message", sk)
{:ok, true} = Guomi.SM2.verify("message", sig, pk)
```

---

## 📊 代码统计

| 文件 | 行数 | 说明 |
|------|------|------|
| `lib/guomi.ex` | 5 | 空壳外观模块 |
| `lib/sm2.ex` | 85 | SM2 实现 |
| `lib/sm3.ex` | 24 | SM3 实现 |
| `lib/sm4.ex` | 149 | SM4 实现 |
| `test/sm2_test.exs` | 161 | SM2 测试 |
| `test/sm3_test.exs` | 61 | SM3 测试 |
| `test/sm4_test.exs` | 137 | SM4 测试 |

**总计**：约 622 行代码（含测试）

---

*分析报告生成时间：2026-03-23*
