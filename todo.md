# TODO

## P0: Correctness and Compatibility

- [x] Fix `test/compare_with_openssl.sh` SM4 hex handling.
  - Current script treats `guomi sm4 --hex` output as raw bytes and pipes it through `xxd -p`, which double-encodes hex text.
  - Make encryption/decryption comparisons use one clear convention: raw bytes or hex text.
  - Acceptance: SM3 and SM4 OpenSSL comparisons pass on an OpenSSL 3.x environment with SM algorithms enabled.

- [x] Define the SM2 compatibility target.
  - Current `Guomi.SM2.encrypt/2` is a simplified ECDH + SM3 KDF + XOR + MAC construction, not clearly documented as standard SM2 encryption.
  - Decide whether to implement standard-compatible SM2 encryption/signature semantics or expose the current code as non-standard helper behavior.
  - Acceptance: README and moduledocs accurately state compatibility limits, or cross-implementation tests pass against OpenSSL where supported.

- [x] Review SM2 sign/verify behavior against standard SM2 expectations.
  - Check signature format, SM3 prehashing behavior, and user ID / ZA handling.
  - Acceptance: tests document the supported signature behavior and, if standard-compatible, include OpenSSL interoperability checks.

## P1: CLI Robustness

- [x] Add explicit required-option validation in `Guomi.CLI`.
  - Validate `--key`, `--iv`, `--private-key`, `--public-key`, `--signature`, and `--ciphertext` before parsing or crypto calls.
  - Acceptance: missing options produce clear stderr messages and exit non-zero.

- [x] Clarify `--hex` semantics for SM4 CLI.
  - Decide whether `--hex` means input hex, output hex, or both.
  - Consider separate flags such as `--input-hex` and `--output-hex` if compatibility allows.
  - Acceptance: help text, README examples, and behavior match exactly.

- [x] Add ExUnit integration tests for CLI behavior.
  - Cover SM3 stdin/file input, SM4 encrypt/decrypt, invalid hex, missing key, invalid mode, and help/version output.
  - Acceptance: CLI tests run as part of `mix test`.

## P2: Crypto Hardening

- [x] Narrow broad `rescue` clauses in crypto modules.
  - Avoid mapping unrelated implementation bugs to `{:error, :unsupported}`.
  - Focus first on `Guomi.SM2`, where `generate_keypair/0`, `sign/2`, `verify/3`, `encrypt/2`, and `decrypt/2` currently rescue all exceptions.
  - Replace broad fallback behavior with explicit validation and clear error reasons such as `:invalid_key`, `:invalid_signature`, `:invalid_ciphertext`, and `:decryption_failed`.
  - Keep `:unsupported` only for genuine runtime capability gaps. Since the current implementation is pure Elixir and `supported?/0` returns `true`, normal invalid input should not be reported as unsupported.
  - Acceptance: malformed SM2 private keys, public keys, signatures, and ciphertexts return deterministic domain errors; unexpected implementation failures still fail loudly in tests.

- [x] Align SM2 tests with the pure-Elixir support model.
  - Remove legacy branches that accept `{:error, :unsupported}` for ordinary SM2 operations.
  - Update invalid-input assertions to match the explicit error reasons introduced by the narrowed error handling.
  - Add regression coverage proving encryption failures are not reported as `:decryption_failed` unless decryption actually fails authentication or ciphertext validation.
  - Acceptance: SM2 tests document always-supported behavior on supported Erlang/OTP versions and no longer mask invalid input as runtime unsupported.

- [x] Fix SM2 signing/verification timeout after explicit error handling.
  - Initial status: `mix format`, `mix compile --warnings-as-errors`, `git diff --check`, and isolated SM2 keypair tests passed.
  - Initial blocker: `mix test test/sm2_test.exs:27 --trace` timed out in the SM2 sign/verify roundtrip path.
  - The old broad rescue paths masked curve arithmetic failures; keypair generation was fixed enough to pass, but signing still needs diagnosis.
  - Investigate `Guomi.SM2.Curve.sign/2`, `sign_with_e/2`, affine scalar multiplication, modular inverse over the curve order, and verify point addition.
  - Resolution: modular inverse now accepts an explicit modulus and SM2 signature scalar arithmetic uses the curve order `n`; regression coverage verifies `mod_inv(2, n)`.
  - Acceptance: `mix test test/sm2_test.exs --trace` and full `mix test` complete without timeout or failures.

- [x] Harden PKCS#7 padding validation.
  - Current validation can return based on padding content differences.
  - Acceptance: invalid padding is rejected consistently, with tests for malformed padding blocks.

- [x] 摆脱对 OpenSSL 的运行时依赖。
  - SM3、SM4、SM2 核心算法已全部替换为纯 Elixir/Erlang 实现，不再依赖 `:crypto` 的国密算法支持。
  - SM2 的椭圆曲线运算（ECDH、ECDSA）使用纯 Elixir 的有限域算术实现点加、倍点、标量乘、模逆。
  - Acceptance: 所有 68 个测试通过，包括官方 KAT 向量和 OpenSSL 兼容性验证。

- [x] Consider adding SM4 CTR APIs for streaming-friendly encryption.
  - Add `encrypt_ctr/4` and `decrypt_ctr/4` only if the API can be specified clearly with a 16-byte nonce/counter block and deterministic counter increment semantics.
  - Do not describe this as GCM-like unless authentication is actually implemented; unauthenticated CTR must be documented as confidentiality-only.
  - Keep ECB/CBC APIs for compatibility, but recommend against ECB for new encryption and warn that CTR nonce reuse is catastrophic.
  - Acceptance: CTR has round-trip tests, counter-boundary tests, known-vector coverage if available, README security notes, and CLI behavior only if the command-line UX is unambiguous.

- [x] Decide whether `cli.md` is release documentation.
  - The file currently exists outside the tracked set. If it is intended as public documentation, include it in `mix.exs` docs extras and package files.
  - If README remains the canonical CLI reference, either remove duplication or keep `cli.md` explicitly scoped as a local development note.
  - Acceptance: package/docs output includes every intended public document and excludes stale duplicate guidance.

## P3: CI and Release Quality

- [x] Add a normal CI workflow for pushes and pull requests.
  - Suggested checks: `mix deps.get`, `mix format --check-formatted`, `mix compile --warnings-as-errors`, `mix test`, `mix credo --strict`.
  - Acceptance: CI runs independently from Hex publish workflow.

- [x] Keep Hex publish workflow focused on releases.
  - The existing `.github/workflows/hex.yml` can stay tag/manual only.
  - Acceptance: release workflow depends on the same quality gates as CI or clearly repeats them.

- [x] Ensure dev dependencies are installable in a fresh checkout.
  - Current local static checks need `mix deps.get` before running.
  - Acceptance: contributor setup instructions mention dependency installation and quality commands.

## P4: Documentation

- [x] Update README examples after CLI hex behavior is finalized.
  - Ensure examples are copy-pasteable and match actual stdin/file behavior.
  - Acceptance: every README CLI example has a matching test or manually verified command.

- [x] Add a compatibility matrix.
  - Document required Erlang/OTP, OpenSSL, and algorithm support for SM2/SM3/SM4.
  - Acceptance: users can tell whether unsupported results are expected on their runtime.

- [x] Document security caveats.
  - Include notes on ECB mode, CBC IV requirements, SM2 compatibility status, and runtime OpenSSL dependency.
  - Acceptance: public docs do not overclaim standards compliance or production safety.
