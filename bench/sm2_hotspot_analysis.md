# SM2 曲线热点性能分析 — 2026-08-19

对应 `todo.md` P2 项：“继续分析 SM2 曲线运算热点；此项只处理性能，标准 KDF 与密文迁移归入 P0”。

## 1. 基准（`mix run bench/bench.exs`）

环境：Elixir 1.14.0 / OTP 25 / ERTS 13.2.2.5 / aarch64-unknown-linux-gnu / 2 schedulers（`bench/bench.exs:57-70`）。5 samples, 1 warmup, `samples=5` `sm2_iterations=20`，min/median/max 统计（`bench/bench.exs:28-38`）。

| 用例 | min/median/max |
|------|----------------|
| SM3 1 MiB | 3.4 / 4.1 / 4.5 MB/s |
| SM3 1 KiB | 0.2 / 4.9 / 5.0 MB/s* |
| SM4 ECB 1 MiB | 9.0 / 12.9 / 14.2 MB/s |
| SM4 CBC 1 MiB | 6.2 / 7.0 / 9.4 MB/s |
| SM4 CTR 1 MiB | 6.0 / 7.5 / 9.1 MB/s |
| SM2 generate_keypair | 2.59 / 2.86 / 5.76 ms/op |
| SM2 sign 32B | 2.69 / 3.69 / 4.54 ms/op |
| SM2 verify | 3.67 / 4.21 / 7.1 ms/op |
| SM2 encrypt 32B | 6.1 / 7.8 / 9.57 ms/op |
| SM2 decrypt 32B | 2.51 / 2.8 / 3.49 ms/op |

* 1 KiB 小样本 `us/op→MB/s` 的分母抖动大，仅作回归对比，不作性能结论（`README.md:296-299` 已声明）。

横向对比（`CHANGELOG.md:35-39` 历史优化）：SM3 滚动窗口 + 预计算 Tj + 特化 rotl；SM2 Jacobian+联合乘法；SM4 T0 表+线性 iodata。当前基准可作为本机回归基线。

## 2. 剖析方法

* `fprof` 全链路：30× sign/verify/generate + 1× encrypt_standard + 20× decrypt_standard。
* `eprof` 细粒度：30× sign/verify。两者均指向 `Curve.mod` 为首要热点。

## 3. 热点分解（`eprof` total 401s 归一化）

```
mod/2              55.10% OWN  221108 独占   581175 总调用
mod_mul/2          18.35%       73611      444411
jac_double/1        7.55%       30304       15872
jac_add_mixed/2     6.65%       26679       12301
add32/2 (SM3)       —           2873        31232  // 非 SM2 主路径
egcd_iter/5         1.03%        4148       14028
do_jac_mul/4        0.64%        2558        8224
p0/p1, rotl*        <0.3% each
```

`fprof` ACC 前五：`mod/2` > `mod_mul` > `jac_add_mixed` > `jac_double` > `egcd_iter`，与 `eprof` 一致。

代码映射：

* `mod/2` `lib/guomi/sm2/curve.ex:21-26`：`value |> rem(modulus) |> Kernel.+(modulus) |> rem(modulus)`，每轮 `jac_double/add` 中多次调用（`mod_sub/mod_mul` 均经此），约 3 次 `rem` + 2 次大整数加法。
* `mod_mul/2` `curve.ex:15` 仅 `mod(a*b)`，热点来自标量乘循环。
* `jac_double` `curve.ex:62-77`：8 次 `mod_mul` + 4 次 `mod_sub`。
* `jac_add_mixed` `curve.ex:80-105`：混合加法 11 次 `mod_mul` 含分支 `h==0`.
* `egcd_iter` `curve.ex:35-40`：扩展欧几里得迭代求逆，仅 `jac_to_affine` `curve.ex:107-113` 末尾 1 次（`sign` 0 次，`verify` 1 次，`generate_keypair` 1 次）。

循环规模：`do_jac_mul/4` `curve.ex:122-133` 与 `do_jac_mul_add/6` `curve.ex:142-158` 均固定 256 轮 double + 条件 add（平均约 128 次 add），与调用次数吻合：`8224 / 256 ≈32` 次标量乘。

## 4. 根因

1. **Erlang 大整数 `rem` 开销**：`p`/`n` 为 256-bit，`a*b` 中间积达 512-bit，`rem` 为通用除法，非 Montgomery 域。
2. **重复归约**：`mod_sub(a,b)=mod(a-b)` 每次先减后归约，`jac_double` 中 `mod_sub(mod_mul(3,a), mod_mul(3,zz²))` 已是归约后值再归约。
3. **逐位循环**：`Bitwise.bsr(k,i) &&&1` 逐位分支，非窗口化，256 轮固定。
4. **单次求逆**：已通过 Jacobian 延迟到最终一次，无法再减；但 `mod_inv` 的 `egcd_iter` 仍是变长时间。

SM3/SM4 未进入 SM2 热路径，排除。

## 5. 优化建议（仅性能，不改变 KDF/密文）

按收益/成本排序，均需保持测试向量与 OpenSSL 互操作：

**P2-1 `mod` 快速路径**（低风险，预期 10-20%）：
```elixir
defp mod(value, modulus) when value >= 0 and value < modulus, do: value
defp mod(value, modulus) when value >= 0, do: rem(value, modulus)
defp mod(value, modulus), do: rem(value, modulus) + modulus |> then(&if &1 >= modulus, do: &1 - modulus, else: &1)
```
避免 `mod_sub` 已归约值上的二次 `rem`；或内联 `mod_sub/mod_mul` 为条件减法：`if r>=modulus, do: r-modulus`.

**P2-2 预计算与窗口化**（中风险，预期 2-4×，但需恒定时间权衡）：
* 4-bit/5-bit 固定窗口 + 预计算 `[1,3,5..15]G` 奇数表，将 `256` 次 double 降为 `256 + 64/51` 次加法；或 wNAF。
* 批量 `jac_to_affine`：验证场景若批处理多签名，可共享一次求逆（Montgomery trick），与当前单次验签正交。

**P2-3 Montgomery 域**（高风险，需重写 `mod_mul/mod_inv`）：
* 将 `p` 域转为 Montgomery 表示，`mod_mul` 变为 `mont_mul`（无 `rem`），配合恒定时间 `mod_inv`（如 Bernstein-Yang）。收益最大但需全量重测；若同时追求侧信道加固可一并考虑。

**P2-4 结构微调**（低风险）：
* `scalar_add/sub/mul` `curve.ex:17-19` 对 `n` 的 `mod` 同 `mod` 优化；
* `generate_private_key`/`generate_k` 的 `binary.decode_unsigned` 可复用 `<<k::256-big>>` 模式匹配，减少一次 BIF；
* `bench` 固定 `schedulers_online` 并 `taskset` 绑核，减少 `max` 抖动。

不建议：BEAM 层面的 `rem` 无法通过 `Bitwise` 绕过；`T0`/`Tj` 等 SM3/SM4 优化已收敛。

## 6. 验收标准

* 任何优化后 `mix test`（含 `test/sm2_test.exs:39-57` 固定向量、`test/openssl_compat_test.exs:262-321` 互操作）必须通过。
* `bench/bench.exs` 同机同参 median 提升 ≥10% 且 max 不劣化 >15% 视为有效；单次 wall-clock 不得作为结论（`bench/bench.exs:28-38` 统计）。
* 若引入窗口/Montgomery，需补充对应侧信道声明（窗口查表引入缓存侧信道，需与 `SECURITY.md:39` 协同）。

## 7. 结论

当前热点集中在 `mod/2` 与 Jacobian 基本运算，属于实现选型而非算法缺陷；短期以 `mod` 快速路径与窗口化取得可观收益，长期视是否需要恒定时间再评估 Montgomery。已满足 `todo.md` “标准 KDF 与密文迁移归入 P0，此项只处理性能” 的边界要求。
