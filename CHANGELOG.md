# Changelog

All notable changes to Guomi are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added SM2 CLI `--user-id <id>` to sign/verify with the standard ZA computation
  (`SM3(ZA || message)`, interoperable raw `r || s`), and `--standard` to
  encrypt/decrypt with the standard `C1 || C3 || C2` format. Without these
  flags the CLI keeps the legacy compatibility behavior. The options are
  rejected outside their applicable operations.
- Added `scripts/openssl_compat.exs` for strict local interoperability checks
  against OpenSSL, including exact SM4 ECB/CBC/CTR ciphertext comparisons and
  bidirectional decryption checks.
- Added strict OpenSSL compatibility and core-library coverage gates to CI;
  CLI coverage remains enforced through black-box integration tests.

### Changed

- `Guomi.SM2.Curve.shared_point/2` and `shared_secret/2` now validate the peer
  point themselves and return `{:error, :invalid_point}` for off-curve input
  instead of relying on callers to reject it.
- `Guomi.SM2.Curve.verify/3` returns `false` for malformed signatures instead
  of raising; `Guomi.SM2` continues to report them as `{:error, :invalid_signature}`.
- SM4 PKCS#7 padding validation now compares all padding bytes without
  short-circuiting, removing a padding-value-dependent timing difference in
  decryption.
- Legacy SM2 encryption XOR no longer materialises a full repeated keystream;
  peak memory now stays proportional to the message size.

## [0.5.2] - 2026-08-19

### Added

- Added `bench/bench.exs` micro-benchmark for the pure-Elixir SM2, SM3, and SM4 cores.
- Benchmark output now records runtime/OS/architecture parameters and reports
  min/median/max across repeated samples.
- Added large-input SM4 CTR coverage and fixed SM2 scalar-multiplication vectors.
- Added explicit standard SM2 APIs for ZA-aware raw signatures and C1/C3/C2
  encryption using the counter-based SM3 KDF; legacy APIs retain their format.

### Changed

- CI now verifies the documented minimum Elixir 1.14/OTP 24 toolchain in addition
  to the current cross-platform toolchain.
- Release jobs now reject tags whose version does not match `mix.exs`.
- Removed the reserved, behaviorless SM2 CLI `--hex` option; SM2 keys,
  signatures, and ciphertext remain hex-encoded where documented.
- Added public API documentation for SM2, SM3, and SM4, and report malformed
  SM2 message iodata as `:invalid_input` instead of `:invalid_key`.
- CLI positional arguments now consistently mean message text; file input uses
  the explicit `--file <path>` option for SM2, SM3, and SM4.
- Added SM4-CTR CLI encryption/decryption with an explicit required 16-byte
  `--counter`; padding options are rejected in CTR mode.
- Added doctests for the documented facade and SM3 examples; CLI examples remain
  covered by subprocess integration tests.
- Optimized SM3 compression with a rolling 16-word message schedule,
  precomputed round constants, and specialized rotations.
- Optimized SM2 scalar multiplication with Jacobian coordinates and mixed
  addition, then optimized verification with joint scalar multiplication.
- Optimized SM4 rounds with a precomputed transform table and changed CBC/CTR
  output assembly from repeated binary concatenation to linear-time collection.
- Preserved LF line endings during Windows CI checkout so formatting checks are
  consistent across Ubuntu, macOS, and Windows.
- CI now runs every compatibility job even when another matrix entry fails, and
  runs the version-sensitive formatter check once on the primary toolchain.
- OpenSSL interoperability tests now encode generated SM2 private keys as PKCS#8,
  allowing current OpenSSL releases to import the fixtures consistently.

### Documentation

- Added an implementation-oriented SM2 standards and migration design covering
  ZA/user IDs, signature encoding, KDF, ciphertext layout, and legacy handling.
- Added a security policy covering SM2 migration, SM4 integrity composition,
  key/randomness handling, side-channel limits, and unsupported use cases.
- Documented reproducible benchmark comparison rules and scoped future streaming,
  certificate parsing, and SM9 work with explicit implementation prerequisites.
- Corrected the README SM3 CLI example and removed unverified performance claims.
- Clarified API return values, binary formats, SM2 interoperability limits, and
  SM2 long-message confidentiality limits and SM4 confidentiality-only mode caveats.
- Aligned CLI input parsing, SM2 output, and SM4 mode documentation with the
  current implementation.
- Synchronized README, standalone CLI documentation, and embedded CLI help;
  added current quality-check and micro-benchmark instructions.
- Updated the Hex release guide and development roadmap.
- Updated the SM2 migration guide to reflect the implemented standard APIs,
  current interoperability coverage, and concrete caller migration steps.

### Fixed

- SM2 private key generation and signature ephemeral scalars now use rejection
  sampling into `[1, n-2]` / `[1, n-1]` instead of a modular reduction,
  removing the modulo bias toward small values.
- Legacy `decrypt/2` now reports an off-curve ephemeral point in `C1` as
  `:invalid_ciphertext` instead of the misleading `:invalid_key`.

## [0.5.1] - 2026-05-31

### Added

- Added SM4 CTR mode with `encrypt_ctr/4` and `decrypt_ctr/4`, using a 16-byte
  big-endian counter block and supporting arbitrary-length input without padding.
- Added CTR coverage for round trips, the first-block SM4 test vector,
  counter increment behavior, counter wraparound, and invalid key/counter sizes.
- Added `cli.md` to published package files and ExDoc extras.

### Changed

- Tightened SM2 error handling so invalid keys, signatures, and ciphertexts
  return deterministic domain errors instead of broad `:unsupported` fallbacks.
- Updated SM2 tests and CLI integration coverage to reflect the pure-Elixir
  always-supported runtime model.
- Updated README support tables, SM4 examples, and security notes for CTR mode.

### Fixed

- Fixed SM2 public key, private key, and raw signature encoding to use fixed
  256-bit big-endian integer fields.
- Fixed SM2 modular inverse so signature scalar arithmetic can use the curve
  order `n` instead of only the field prime `p`.
- Fixed SM2 signing timeout caused by `s == 0` retry loops when modular inverse
  over `n` returned `0`.
- Fixed affine point arithmetic edge cases that were previously hidden by broad
  rescue clauses.

## [0.5.0] - 2026-05-16

### Added

- Pure Elixir SM3 implementation — replaces the previous `:crypto.hash(:sm3, ...)`
  dependency. SM3 is now fully implemented in Elixir with proper padding, block
  processing, and the GM/T 0004-2012 compression function.
- Pure Elixir SM4 implementation — replaces the previous `:crypto.crypto_one_time`
  dependency. Full S-box lookup, key expansion, ECB and CBC modes, and PKCS#7
  padding are implemented in Elixir (GM/T 0002-2012).
- Pure Elixir internal SM2 curve arithmetic — Jacobian projective
  coordinate elliptic curve operations over the SM2 p256v1 curve, including point
  doubling, addition, scalar multiplication, modular inverse, ECDH shared secret,
  and ECDSA-compatible sign/verify primitives.
- Internal module with low-level SM2 elliptic curve operations.
- Additional test coverage for block boundaries, padding edge cases, empty input,
  invalid key/ciphertext sizes, PKCS#7 padding validation, CBC mode with binary
  data, and CLI empty input handling.

### Changed

- `Guomi.SM2.supported?/0`, `Guomi.SM3.supported?/0`, and `Guomi.SM4.supported?/0`
  now return `true` unconditionally — all algorithms are implemented in pure
  Elixir and no longer require runtime OpenSSL SM algorithm support.
- `Guomi.SM3.hash/1` and `Guomi.SM3.hash_hex/1` now accept iodata input.
- `Guomi.SM4.encrypt/2`, `Guomi.SM4.decrypt/2`, `Guomi.SM4.encrypt_cbc/3`,
  `Guomi.SM4.decrypt_cbc/3` no longer depend on OTP `:crypto` SM4 primitives.
- `Guomi.SM2.generate_keypair/0`, `Guomi.SM2.sign/2`, `Guomi.SM2.verify/3`,
  `Guomi.SM2.encrypt/2`, `Guomi.SM2.decrypt/2` no longer depend on OTP
  `:crypto` ECDH/ECDSA primitives.
- Simplified CLI error handling — removed the `:unsupported` error variant for
  SM2 since it is always supported at runtime.
- Renamed internal `extract_shared_secret/1` to direct big-endian encoding in
  SM2 encryption/decryption.

### Removed

- Runtime `:crypto` dependency for SM3 hashing, SM4 encryption, and SM2 curve
  operations. The OTP `:crypto` module is now only used for `:crypto.exor/2`
  (XOR helper) and `:crypto.strong_rand_bytes/1` (random key generation).

## [0.4.2] - 2026-05-16

### Changed

- Refactored CLI, SM2, SM4, and OpenSSL compatibility test code to satisfy Credo strict checks.
- Normalized source file line endings for Credo consistency checks.

## [0.4.1] - 2026-05-16

### Changed

- Made SM3, SM4, CLI, and OpenSSL compatibility tests runtime-aware when CI OpenSSL lacks Guomi algorithm support.

### Fixed

- Added a friendly SM3 CLI error when the runtime does not support SM3.

## [0.4.0] - 2026-05-16

### Added

- Added a unified Hex workflow that runs CI checks for pushes and pull requests, then publishes only for `v*` tags or manual dispatch.
- Added `Guomi.algorithms/0` to list the algorithms exposed by the package.
- Added `Guomi.supported/0` to report SM2, SM3, and SM4 runtime support in one call.
- Added CLI integration tests for help/version output, SM3 input, SM4 encryption/decryption, invalid hex, missing keys, and invalid modes.
- Added ExUnit-based OpenSSL compatibility tests for SM3 and SM4 CLI behavior.
- Added coverage for the new facade APIs, runtime support checks, SM2 signature format, and malformed SM4 padding.
- Added README compatibility and security notes for runtime support, SM2 interoperability limits, ECB mode, and CBC IV usage.

### Changed

- Hardened SM2 decryption by validating ciphertext size before parsing and reducing intermediate allocations.
- Hardened SM4 runtime support detection so capability lookup failures return `false` instead of raising.
- Wrapped SM4 `:crypto.crypto_one_time/5` calls for more consistent success/error handling.
- Improved CLI hex parsing by trimming surrounding whitespace before decoding.
- Clarified SM4 CLI hex semantics and added explicit `--input-hex` and `--output-hex` options.
- Refactored CLI input reading, output encoding, and error reporting into shared helpers.

### Fixed

- Fixed SM4 CLI padding parsing so only `pkcs7` and `none` are accepted.
- Fixed CLI hex ciphertext decoding paths to return friendly validation errors.
- Fixed required-option validation for CLI keys, IVs, signatures, and SM2 keys.

### Removed

- Removed the separate CI workflow in favor of the unified Hex workflow.
- Removed the bash OpenSSL comparison script in favor of ExUnit tests.

## [0.3.0] - 2026-04-05

### Added

- Added the `Guomi.CLI` escript entry point.
- Added CLI commands for SM2, SM3, and SM4 operations.
- Added CLI `version` and `help` commands.
- Added an OpenSSL comparison script for CLI validation.

### Changed

- Updated package metadata to build the CLI as an escript.
- Updated README and changelog content for the `0.3.0` release.
- Formatted CLI code and removed an unused SM2 error-formatting clause.

### Removed

- Removed the obsolete `README.kimi.md` document.

## [0.2.0] - 2026-04-01

### Added

- Added SM2 encryption and decryption support.
- Added `Guomi.SM2.encrypt/2` and `Guomi.SM2.decrypt/2`.
- Expanded SM2 tests and documentation.
- Added project structure improvements, formatter configuration, CI configuration, and development dependencies.

### Changed

- Updated SM4 handling and project metadata as part of the broader project cleanup.
- Updated the package version to `0.2.0`.

## [0.1.0] - 2026-03-28

### Added

- Initial Hex package release.
- Added SM2 key generation, signing, verification, encryption, and decryption.
- Added SM3 hashing with binary and hexadecimal output.
- Added SM4 ECB and CBC encryption/decryption.
- Added `:pkcs7` and `:none` padding support for SM4.
- Added runtime support detection for SM2, SM3, and SM4.
- Added the initial test suite.
- Added ExDoc documentation setup and package metadata.

[Unreleased]: https://github.com/ZeroMarker/guomi/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/ZeroMarker/guomi/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/ZeroMarker/guomi/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/ZeroMarker/guomi/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/ZeroMarker/guomi/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/ZeroMarker/guomi/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ZeroMarker/guomi/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ZeroMarker/guomi/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ZeroMarker/guomi/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ZeroMarker/guomi/releases/tag/v0.1.0
