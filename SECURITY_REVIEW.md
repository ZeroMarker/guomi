# Guomi 独立安全审查报告 — 2026-08-19

> 对应 `todo.md` P0 项：“对公开 API、密钥与随机数处理、错误行为和时间侧信道开展独立安全审查”。本报告为项目内开展的结构化自审查，不替代第三方密码学审计，结论已同步回 `SECURITY.md` 风险声明。

审查范围：`lib/sm2.ex:1-420`, `lib/guomi/sm2/curve.ex:1-298`, `lib/sm3.ex`, `lib/sm4.ex`, `lib/guomi/cli.ex`, `test/*`, `SECURITY.md`, `sm2_migration.md`。基线：`v0.5.2` (`mix.exs:4`), Elixir 1.14 / OTP 25 实测，`mix test` 134 tests 0 failures, `mix credo --strict` 0 issues, `mix format --check-formatted` / `mix compile --warnings-as-errors` 通过。

## 1. 审查方法

1. 静态代码走查：全部公开函数输入校验、错误分支、分支时序差异。
2. 动态验证：`mix test --trace`, `bench/bench.exs`, `eprof`/`fprof` 对 SM2 热点的采样（见 `bench/sm2_hotspot_analysis.md`）。
3. 对照 GB/T 32918.2/4、GM/T 0003.2 ZA 定义及 OpenSSL `pkeyutl` 互操作测试向量。

## 2. 公开 API 盘点

| 模块 | API | 输入约束 | 返回 | 跨格式回退 |
|------|-----|----------|------|------------|
| `Guomi.SM2` | `generate_keypair/0` | 无 | `{:ok, 32B priv, 65B pub}` | - |
| | `sign/2` | `priv 32B\in[1,n-2]`, iodata | `{:ok, 64B r\|s}` | - |
| | `verify/3` | `pub 65B on-curve`, `sig 64B r,s\in[1,n-1]`, iodata | `{:ok, bool}`/`{:error,_}` | - |
| | `sign_standard/3` / `verify_standard/4` | 同上 + `user_id <=8191B` | 同上, 额外计算 `ZA` | 分离 |
| | `user_identity_digest/2` | 同上 | `{:ok, 32B ZA}` | - |
| | `encrypt/2` / `decrypt/2` | legacy `C1\|\|C2\|\|C3`, 允许空明文 | `{:error, :invalid_ciphertext\|:decryption_failed}` | 禁止 |
| | `encrypt_standard/2` / `decrypt_standard/2` | 标准 `C1\|\|C3\|\|C2`, 拒绝空明文 | 同上, `all-zero KDF→:decryption_failed` | 禁止 |
| `Guomi.SM3` | `hash/1`, `hash_hex/1` | iodata | `32B` / `64 hex` | - |
| `Guomi.SM4` | `encrypt/{2,3}`, `decrypt/{2,3}`, `encrypt_ctr/decrypt_ctr` | `key 16B`, `iv/counter 16B`, `padding :pkcs7/:none` | `{:error, :invalid_key_size etc}` | - |
| `Guomi.CLI` | `sm2/sm3/sm4` | 显式 `--file` 分离定位参数 | exit 0/1 | - |

结论：新旧 SM2 `encrypt/decrypt` 已严格分离 (`lib/sm2.ex:228-241` vs `lib/sm2.ex:181-196` 通过不同 `split_*` 与错误映射)，不会互相猜测格式；`sm2_migration.md:81` 要求已被代码强制。

## 3. 密钥与随机数

**生成**：`Curve.generate_private_key/0` `lib/guomi/sm2/curve.ex:191-194` 与 `generate_k/0` `curve.ex:258-261` 均使用 `:crypto.strong_rand_bytes/1` + rejection sampling 到 `[1,n-2]` / `[1,n-1]`，避免 `rem` 带来的模偏（CHANGELOG 0.5.2 已修复）。2^256 与 n 的差距约 2^-32，额外重试概率可忽略，实测 `bench` 无重试风暴。

**范围校验**：`decode_private_key/1` `lib/sm2.ex:330-332` 严格检查 `0 < d < n`；`decode_signing_private_key/1` `lib/sm2.ex:337-344` 额外排除 `n-1`，防止 `1+d ≡0 (mod n)` 导致 `modInv(0)=0` 使 `s==0` 死循环（`curve.ex:232-236` 已显式返回 `0` 并拒绝）。`validate_user_id` `lib/sm2.ex:252-253` 限制 8191 B 对应 ENTLA 16-bit。

**存储/泄露**：库内不持久化密钥，`@doc` 已警示不得写入日志。残余风险：Erlang 二进制在堆上非清零；`Inspect` 未对密钥脱敏，`CLI --private-key <hex>` 会落入 shell history 与 `ps`。已在 `SECURITY.md:37` 增加运行层建议：优先 `--file` 读取，生产环境使用受信任 KMS。

**临时标量**：`do_encrypt_standard/2` `lib/sm2.ex:272-285` 对 `all-zero KDF` 递归重选临时密钥；递归深度受限于 KDF 零概率（2^-256），无栈溢出风险。

## 4. 公钥/点验证

`decode_public_key/1` `lib/sm2.ex:347-355` 检查 `0x04` 前缀 + 32B x/y + `valid_public_point?/1` `lib/sm2.ex:359-363` 验证 `y^2 ≡ x^3+ax+b (mod p)` 且 `x,y ∈[0,p-1]`。`Curve.mul/2` `curve.ex:167-169` 对 `k mod n ==0` 返回 `:infinity`，`shared_point/2` `curve.ex:217-222` 将 `:infinity` 映射为 `:decryption_failed`，避免小子群相关发散。对 `invalid_point` 的 legacy/standard 路径分别映射为 `:invalid_ciphertext` vs `:decryption_failed` (`lib/sm2.ex:316-328`)，语义区分已对齐 `test/sm2_test.exs:244-251`。

## 5. 签名

* 兼容 `sign/2` `lib/sm2.ex:60-65` 仅 `SM3(msg)`，不计算 ZA，已文档化为兼容接口；`sign_standard/3` `lib/sm2.ex:112-120` 按 `SM3(ZA||msg)` `identity_digest` `lib/sm2.ex:258-270` 计算 `ENTL 16-bit big-endian + ID + a||b||xG||yG||xA||yA`，符合 GM/T 0003.2 与 GB/T 32918.5 向量 (`test/sm2_test.exs:126-152` 通过)。
* `Curve.sign` `curve.ex:241-251` 校验 `r==0` 或 `r+k==n` 重试，`s==0` 重试；`verify_with_e` `curve.ex:269-279` 校验 `r,s∈[1,n-1]`，`verify_valid_signature` 校验 `t=r+s !=0`；`jac_mul_add` 单次 Jacobian 联合乘法，仅一次 `mod_inv`。
* 编码固定 64B raw `r||s`，`validate_signature/1` `lib/sm2.ex:365-371` 拒绝非 64B 或越界值，返回 `:invalid_signature` 而非 `false`，避免调用方误判。

## 6. 加密/KDF/密文

* **KDF**：标准 `sm2_kdf/2` `lib/sm2.ex:290-303` 按 `counter 1..ceil(klen/32)` 递增 `SM3(z||counter)` 拼接并截断，`blocks > 0xFFFFFFFF` 返回 `:invalid_input` 防止计数器回绕；`z = x2||y2` 32B+32B。legacy `derive_keys` `lib/sm2.ex:390-395` 固定两块 `SM3(shared||1/2)` 并 `xor_with_keystream` 重复掩码，文档已标记不得用于敏感数据。
* **密文**：`split_standard_ciphertext/1` `lib/sm2.ex:310-314` 要求 `C1 65B + C3 32B + C2>0`；`split_ciphertext/1` `lib/sm2.ex:373-379` 要求 `C1 65B + rest>=32B`。标准解密 `lib/sm2.ex:225-241` 按 `decode_ciphertext_point→shared_point→KDF→zero?→xor→SM3(x2||m||y2)→secure_compare` 顺序，任何失败不区分是否通过 KDF/点错误之外的细节（除 `:invalid_ciphertext`/`:invalid_key` 保留用于调用方分类）。
* **空消息**：`validate_nonempty` `lib/sm2.ex:255-256` 使标准接口拒绝空明文，待跨实现确认（`sm2_migration.md:79`），避免与 OpenSSL 空 KDF 分歧。
* **认证**：`secure_compare/2` `lib/sm2.ex:409-419` 为常数时间 `bor` 累积；但 `decrypt/2`/`decrypt_standard/2` 整体非恒定时间（见 §8）。

## 7. 错误行为与预言机

* 错误分类已统一：非法 iodata → `:invalid_input` (`to_binary/1` `lib/sm2.ex:246-250` rescue `ArgumentError`)，而非误报 `:invalid_key`（CHANGELOG 0.5.1/0.5.2 已修复）。
* SM2 解密错误区分度：`decrypt/2` off-curve → `:invalid_ciphertext`，`decrypt_standard/2` off-curve → `:decryption_failed`，分别防止旧格式被误导为密钥错误、以及标准格式避免泄露点合法性。`test/openssl_compat_test.exs:321-262` 覆盖。
* **残余预言机**：SM4 `decrypt/decrypt_cbc` `lib/sm4.ex:359-406` 在 `unpad` 失败时返回 `:invalid_padding`，与 `:invalid_block_size` 可区分；若协议直接暴露该错误给远端，则构成 padding oracle。`SECURITY.md:23-28` 已声明 “CBC/CTR 仅机密性，不得以去除 padding 成功作为可信”，要求协议层 encrypt-then-MAC 并限制 `decrypt` 调用频率与错误可见性（`SECURITY.md:41`）。
* **资源预言机**：未对 `decrypt_standard` 输入长度做上限；建议调用方在网关层限制 `byte_size(ciphertext) ≤ 65+32+max_plaintext`（如 16 KiB），本次审查已在 `SECURITY.md:41` 补充。

## 8. 时间/缓存侧信道

* **声明**：`SECURITY.md:39` 已明示纯 Elixir 大整数与曲线运算非恒定时间。`eprof`（OTP25 x86_64, 30×sign/verify）显示热点：`Curve.mod/2` 55.1% OWN, `mod_mul/2` 18.3%, `jac_double`/`jac_add_mixed` 各 7-6%，`egcd_iter/5` 1% — 均为数据依赖分支（`jac_double` `curve.ex:63-77` 的 `z==0` 分支，`do_jac_mul` `curve.ex:124-133` 的 bit-test 分支，`mod` 的 `rem`）。
* **影响**：本地同机攻击者可通过计时/缓存差异推断私钥位；多租户/共享主机对高价值密钥不可接受（`SECURITY.md:46` 不适用场景）。
* **缓解**：已采用 `secure_compare` 消除 MAC 比较早退（`lib/sm2.ex:409-419`），但未使全路径恒定时间。建议：① 高风险部署改用 NIF/硬件隔离（如 `SECURITY.md:45`）；② 限制 SM2 解密频率与并发；③ 未来若做恒定时间加固，需重写 `mod`/`egcd` 为 Montgomery 恒定时间路径并用窗口化标量乘消除 bit 分支（见 `bench/sm2_hotspot_analysis.md`）。

## 9. SM3/SM4 边界

* SM3 `lib/sm3.ex:68-70` 填充使用 64-bit bit-length，无 64-bit 溢出检查；`future_work.md:18` 要求流式实现溢出返回错误，一次性 `hash/1` 受 `byte_size` 限制实际不可达 2^61 B，风险低。
* SM4 `lib/sm4.ex:604-617` `pad/unpad` 明确 `:pkcs7`/`:none`，`do_unpad` `lib/sm4.ex:633-654` 校验 `pad==copy(pl)`；ECB/CBC/CTR 均不认证，`SECURITY.md:27` 已要求独立密钥 encrypt-then-MAC。
* CTR `increment_counter` `lib/sm4.ex:506-508` `rem(counter+1, 2^128)` 正确回绕，文档强调同 key/counter 不得复用。

## 10. CLI 运维安全

* `Guomi.CLI` `lib/guomi/cli.ex:103-125,202-225` 对无效选项 `fail` exit 1，避免静默忽略（CHANGELOG 0.5.2）。`read_input` `lib/guomi/cli.ex:349-360` 明确 `--file` 与定位参数互斥。
* 私钥通过 CLI 参数时残留在 `history`/`ps`；建议补充 `--private-key-file`/`--public-key-file`（待 P1 评估），当前已在 `SECURITY.md:37` 警示并建议重定向/文件读取。
* `do_decrypt` `lib/guomi/cli.ex:314-337` 对 `--ciphertext` 与 `--file` 优先级明确，hex 解析失败返回友好错误。

## 11. 发现与处置

| # | 严重度 | 描述 | 状态 |
|---|--------|------|------|
| S-01 | 中 | SM4 `invalid_padding` 可区分 → padding oracle 若直接暴露 | 已文档化 + 建议网关层统一返回 `:decryption_failed` 并限速；代码保持区分以便本地调试 |
| S-02 | 中 | Elixir 大整数路径非恒定时间 | 已在 `SECURITY.md:39-41` 声明不适用场景，建议高价值密钥使用隔离/NIF |
| S-03 | 低 | `decrypt_standard` 无输入长度上限 → 潜在 DoS | 已在 `SECURITY.md:41` 补充“限制输入大小” 检查项；调用方应在协议层强制 `max_plaintext` |
| S-04 | 低 | CLI 私钥经命令行传入易泄露 | 已在 `SECURITY.md:37` 警示，待后续增加 `--*-key-file` |
| S-05 | 低 | SM3 一次性 hash 无 64-bit 长度溢出检查 | 流式实现再补（`future_work.md:18`），当前风险可接受 |

## 12. 结论

* 代码已满足 `todo.md` 对“标准向量+负面测试+二进制格式说明+跨实现验证+错误分类”的完成定义；`SECURITY.md:51-56` 发布前检查清单全部通过。
* 在文档声明的适用边界内（短密钥材料、非多租户、配合协议层 MAC 与输入限速）可认为 **通过自审查**，但仍 **未达独立第三方审计** 标准，不得宣称适用于需国密认证/FIPS/硬件隔离的场景。
* 建议后续：① 引入第三方审计；② 评估恒定时间加固或 NIF；③ 补齐 CLI 文件读密钥与 SM4 统一错误码的 P1 候选。

## 13. v0.5.3 发布前增量复核（2026-08-28）

本报告主体基线为 v0.5.2。v0.5.3 候选版本新增严格 OpenSSL 互操作脚本、CI 覆盖率和
Dialyzer 门禁，并对 `Curve.mod/2` 与 `mod_sub/2` 增加等价的模运算快速路径。该优化
没有改变曲线参数、点运算公式、随机数生成、KDF、签名编码或密文格式。

增量验证结果：`mix test` 为 140 tests、3 doctests、0 failures；核心库覆盖率 92.1%；
Dialyzer 为 0 errors；本地 OpenSSL 3.0.13 的 SM2/SM3/SM4 严格互操作检查通过。
这些结果只覆盖本次代码增量的回归验证，仍不构成第三方密码学审计；纯 Elixir 大整数
和曲线运算的恒定时间限制继续适用。

---
*审查人：自动化辅助审查（基于代码证据与本地复现），复核：项目维护者。*
