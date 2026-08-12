# SM2 标准兼容与迁移设计

本文定义 Guomi 从内部兼容 SM2 构造迁移到标准 SM2 签名和加密接口的边界。本文是实现约束，不代表尚未落地的 API 已可使用。

## 目标与非目标

目标：

- 提供包含用户 ID 与 ZA 的标准 SM2 签名和验签。
- 提供使用标准 KDF、不会重复 XOR 掩码的 SM2 加密和解密。
- 保留读取现有 Guomi 数据所需的显式兼容入口。
- 让调用方能够从 API 或封装版本确定格式，禁止通过密文长度猜测格式。

非目标：

- 不把本库描述为经过认证或独立审计的密码产品。
- 不在同一个解密函数中自动尝试多种密文排列。
- 不把裸 SM4 CBC/CTR 包装成经过认证的加密模式。

## 标准依据

- GB/T 32918.2-2016：SM2 数字签名算法。
- GB/T 32918.4-2016：SM2 公钥加密算法。
- GM/T 0003.2-2012：定义 `ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)`。
- OpenSSL `pkeyutl` SM2 文档：签名和验签必须使用一致的 distinguishing ID。
- RFC 9563：确认推荐曲线参数及 32 字节 `r || s` 编码的一个公开应用配置。

参考链接：

- <https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=370AF152CB5CA4A377EB4D1B21DECAE0>
- <https://www.rfc-editor.org/rfc/rfc9563.html>
- <https://docs.openssl.org/master/man1/openssl-pkeyutl/>

## 签名 API 决策

现有 `sign/2` 和 `verify/3` 只处理 `SM3(message)`，继续作为旧兼容接口存在并标记弃用。标准接口使用不同名称，避免同一调用在升级后产生不同签名：

```elixir
Guomi.SM2.sign_standard(message, private_key, user_id)
Guomi.SM2.verify_standard(message, signature, public_key, user_id)
Guomi.SM2.user_identity_digest(user_id, public_key)
```

约束：

- `user_id` 必须由调用方显式传入，不设置库级隐式默认值。
- `user_id` 是二进制，长度以 bit 计并编码为 16 位大端 `ENTLA`，因此不得超过 8191 字节。
- ZA 固定使用当前 SM2 推荐曲线参数和调用方公钥。
- 第一阶段签名编码固定为 64 字节 raw `r || s`。
- DER 编码不混入第一阶段 API；如后续增加，应通过显式选项或单独转换函数提供。
- 格式正确但验签失败返回 `{:ok, false}`；输入格式错误返回明确的 `{:error, reason}`。

## 加密 API 与密文决策

现有 `encrypt/2`、`decrypt/2` 继续只处理旧 Guomi `C1 || C2 || C3` 兼容格式，并标记弃用。标准接口使用不同名称：

```elixir
Guomi.SM2.encrypt_standard(plaintext, public_key)
Guomi.SM2.decrypt_standard(ciphertext, private_key)
```

第一阶段标准裸密文固定为 `C1 || C3 || C2`：

- C1：65 字节未压缩临时公钥 `0x04 || x1 || y1`。
- C3：32 字节 `SM3(x2 || plaintext || y2)`。
- C2：`plaintext XOR KDF(x2 || y2, byte_size(plaintext))`。
- KDF：按 32 位大端计数器 `1..ceil(klen/32)` 扩展 SM3 输出，禁止计数器回绕。
- 若非空消息得到全零 KDF，生成端必须重新选择临时密钥；解密端必须拒绝。
- 空消息行为必须先由跨实现测试确认；确认前标准加密接口返回 `:invalid_input`。

`decrypt_standard/2` 只解析 `C1 || C3 || C2`，`decrypt/2` 只解析旧格式。两者不得互相回退。

如果未来需要单一持久化字段承载多版本密文，应由应用层或新增 envelope API 添加 magic 和版本号，例如：

```text
"GMS2" || version || format || ciphertext
```

标准裸密文本身不添加私有前缀，以保留互操作能力。

## 迁移步骤

1. 发布标准签名、ZA、标准加密和标准解密 API；旧 API 保持原行为。
2. 使用官方向量验证 ZA/签名，使用独立实现完成签名和密文双向测试。
3. 在一个次版本中将旧 API 标记 deprecated，并在文档中删除新用法示例。
4. 调用方按数据来源选择显式解密入口，再将成功读取的旧密文重新加密为标准格式。
5. 只有在一个主版本升级中才考虑删除旧加密入口；不得静默改变 `decrypt/2` 的格式。

## 测试与验收

- ZA、签名和验签必须有公开标准向量。
- KDF 必须覆盖 0、1、31、32、33 字节及多块长消息边界。
- 密文测试必须覆盖 C1 非法点、截断、C3 篡改、C2 篡改、全零 KDF 和错误私钥。
- 与至少一种独立实现完成签名、验签、加密、解密双向验证。
- 互操作测试不可运行时必须明确 skip 原因，不得把未执行当作通过。
- 独立安全审查完成前，标准接口仍需保留“未经审计”的生产使用警告。
