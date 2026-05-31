# Guomi CLI 使用说明

命令行工具提供 SM2/SM3/SM4 国密算法的直接操作能力。所有算法均为纯 Elixir 实现，无需运行时 OpenSSL 支持。

## 安装

```bash
mix escript.build
```

编译后在项目目录生成 `guomi`（Windows 下为 `guomi.exe`）。

## 全局用法

```bash
guomi <command> [options] [input]
```

## 命令一览

| 命令 | 说明 |
|------|------|
| `sm3` | 计算 SM3 哈希 |
| `sm4` | SM4 加密/解密 |
| `sm2` | SM2 密钥生成、签名/验签、加密/解密 |
| `version` | 显示版本信息 |
| `help` | 显示帮助信息 |

---

## sm3 — SM3 哈希

### 用法

```
guomi sm3 [options] [input]
```

### 选项

| 选项 | 说明 |
|------|------|
| `--hex` | 十六进制输出（默认输出原始二进制） |
| `--help` | 显示帮助信息 |

### 输入来源（优先级从高到低）

1. `--message` 参数（仅 sign/verify/encrypt 命令）
2. 命令行剩余参数（如 `guomi sm3 "hello"`）
3. 文件路径参数（如 `guomi sm3 file.txt`）
4. 标准输入 stdin（如 `echo "hello" \| guomi sm3`）

### 示例

```bash
# 从 stdin 读取，输出十六进制哈希
echo -n "hello" | guomi sm3 --hex
#=> becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268

# 从参数读取
guomi sm3 --hex "hello world"

# 从文件读取
guomi sm3 --hex document.txt

# 输出原始二进制（默认）
echo -n "hello" | guomi sm3
```

### 参考

SM3("abc") 标准测试向量：

```bash
echo -n "abc" | guomi sm3 --hex
#=> 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

---

## sm4 — SM4 加密/解密

### 用法

```
guomi sm4 [options] [input]
```

### 选项

| 选项 | 说明 |
|------|------|
| `--mode <ecb\|cbc>` | 加密模式，默认 `ecb` |
| `--key <hex>` | **必填**。16 字节密钥，十六进制编码 |
| `--iv <hex>` | CBC 模式必填。16 字节初始向量，十六进制编码 |
| `--decrypt` | 解密模式（默认加密） |
| `--hex` | 快捷方式：加密时输出 hex，解密时输入为 hex |
| `--input-hex` | 输入视为十六进制文本 |
| `--output-hex` | 输出为十六进制文本 |
| `--padding <pkcs7\|none>` | 填充方式，默认 `pkcs7` |
| `--help` | 显示帮助信息 |

### 安全提示

- **ECB 模式**只适合测试或兼容遗留系统，**不建议用于新数据加密**
- **CBC 模式**必须为每次加密使用**不可预测且不复用**的 16 字节 IV
- 同一密钥下 IV 复用会完全破坏机密性

### 示例

```bash
# ECB 加密，输出原始密文
echo "secret data" | guomi sm4 --key 0123456789abcdef0123456789abcdef

# ECB 加密，输出十六进制密文
echo "secret data" | guomi sm4 --key 0123456789abcdef0123456789abcdef --hex

# ECB 解密（输入为十六进制密文）
guomi sm4 --decrypt --hex --key 0123456789abcdef0123456789abcdef < ciphertext.hex

# CBC 加密
echo "secret data" | guomi sm4 --mode cbc \
  --key 0123456789abcdef0123456789abcdef \
  --iv 00112233445566778899aabbccddeeff

# CBC 解密
guomi sm4 --decrypt --mode cbc \
  --key 0123456789abcdef0123456789abcdef \
  --iv 00112233445566778899aabbccddeeff < ciphertext.bin

# --hex 模式解密
guomi sm4 --decrypt --mode cbc \
  --key 0123456789abcdef0123456789abcdef \
  --iv 00112233445566778899aabbccddeeff \
  --hex < ciphertext.hex

# 显式控制 hex 输入/输出
echo -n "736563726574" | guomi sm4 \
  --input-hex --output-hex \
  --key 0123456789abcdef0123456789abcdef

# 无填充（输入必须是 16 字节对齐）
echo -n "abcdefghijklmnop" | guomi sm4 \
  --key 0123456789abcdef0123456789abcdef \
  --padding none
```

---

## sm2 — SM2 密钥生成、签名/验签、加密/解密

### 用法

```
guomi sm2 [options] [input]
```

### 通用选项

| 选项 | 说明 |
|------|------|
| `--generate` | 生成密钥对 |
| `--sign` | 签名 |
| `--verify` | 验签 |
| `--encrypt` | 加密 |
| `--decrypt` | 解密 |
| `--private-key <hex>` | 私钥（32 字节，十六进制） |
| `--public-key <hex>` | 公钥（65 字节，04 前缀 + 32 字节 x + 32 字节 y，十六进制） |
| `--message <msg>` | 待签名/验签/加密的消息文本 |
| `--signature <hex>` | 签名值（64 字节 raw r \|\| s，十六进制，仅验签） |
| `--ciphertext <hex>` | 密文（十六进制，仅解密） |
| `--hex` | 输出为十六进制 |
| `--help` | 显示帮助信息 |

### 兼容性说明

- 签名算法使用 SM3 预哈希 + raw 64 字节 `r || s` 格式，未暴露用户 ID/ZA 参数
- 加密使用 Guomi 内部 `C1 || C2 || C3` 格式（C1=65 字节临时公钥, C3=32 字节 SM3 MAC），适用于 Guomi 自身加解密往返
- **不应假定可与 OpenSSL 或其他 SM2 实现互通**

### 示例

```bash
# 生成密钥对
guomi sm2 --generate
#=>
# Private Key:
# <32-byte-hex>
# Public Key:
# <65-byte-hex>

# 签名（从 stdin 读取消息）
echo "message to sign" | guomi sm2 --sign --private-key <hex-key>

# 签名（从 --message 参数读取）
guomi sm2 --sign --private-key <hex-key> --message "hello"

# 验签
guomi sm2 --verify \
  --public-key <hex-pubkey> \
  --signature <hex-signature> \
  --message "hello"

# 验签（从文件读取消息）
guomi sm2 --verify \
  --public-key <hex-pubkey> \
  --signature <hex-signature> \
  message.txt

# 加密
echo "secret message" | guomi sm2 --encrypt --public-key <hex-pubkey>

# 解密
guomi sm2 --decrypt \
  --private-key <hex-privkey> \
  --ciphertext <hex-ciphertext>

# 解密（从文件读取密文）
guomi sm2 --decrypt \
  --private-key <hex-privkey> \
  --ciphertext "$(cat ciphertext.hex)"
```

---

## 常见问题

### Q: `guomi sm3 --hex` 和 `guomi sm3` 输出有什么区别？

`--hex` 输出 64 字符十六进制小写字符串，末尾换行。不指定时输出原始 32 字节二进制数据，适合管道传递。

### Q: SM4 的 `--hex`、`--input-hex`、`--output-hex` 有什么区别？

| 标志 | 加密时 | 解密时 |
|------|--------|--------|
| `--hex` | 输出 hex | 输入为 hex |
| `--input-hex` | 输入为 hex | 输入为 hex |
| `--output-hex` | 输出 hex | 输出 hex |
| 无 | 输入/输出均为原始二进制 | 输入/输出均为原始二进制 |

### Q: SM2 生成的密钥对格式是什么？

- **私钥**: 32 字节大端整数，十六进制编码（64 字符）
- **公钥**: 65 字节，`0x04` 前缀 + 32 字节 x 坐标 + 32 字节 y 坐标，十六进制编码（130 字符）

### Q: Windows 下 `guomi` 运行报 `SetConsoleMode` 错误怎么办？

这是 OTP 28 在 Windows 上的兼容性问题。在运行前设置环境变量可绕过：

```cmd
set ELIXIR_ERL_OPTIONS=-noinput
guomi sm3 --hex "hello"
```

或一次性命令：

```cmd
set ELIXIR_ERL_OPTIONS=-noinput && guomi sm3 --hex "hello"
```

### Q: 返回码约定？

| 场景 | 退出码 |
|------|--------|
| 操作成功 | 0 |
| 输入错误/参数缺失 | 1 |
| 验签失败（签名无效） | 1 |
| SM2 不支持 | 1 |
