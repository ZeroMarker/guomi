# Changelog

All notable changes to Guomi are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Optimized the pure-Elixir crypto cores (no API changes):
  - SM3: replaced the per-block message-expansion Map with a rolling 16-word
    window carried through the 64 rounds, precomputed T_j constants, and
    shift-specialized rotations. Throughput roughly tripled (~5.9 MB/s for 1 MiB).
  - SM2: scalar multiplication now uses Jacobian coordinates with a single
    modular inversion per multiplication instead of one extended-Euclid per
    point operation. Key generation/sign ~5x faster, verify/encrypt ~4x faster.
  - SM4: the round transform L(tau(x)) is evaluated from a precomputed 256-entry
    byte table instead of per-byte S-box lookups plus rotations. Throughput
    roughly doubled (~9.7 MB/s for 1 MiB ECB).

### Added

- Added `bench/bench.exs` micro-benchmark (`mix run bench/bench.exs`).

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
- Pure Elixir SM2 curve arithmetic (`Guomi.SM2.Curve`) — Jacobian projective
  coordinate elliptic curve operations over the SM2 p256v1 curve, including point
  doubling, addition, scalar multiplication, modular inverse, ECDH shared secret,
  and ECDSA-compatible sign/verify primitives.
- `Guomi.SM2.Curve` module with low-level SM2 elliptic curve operations.
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

[Unreleased]: https://github.com/ZeroMarker/guomi/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/ZeroMarker/guomi/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/ZeroMarker/guomi/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/ZeroMarker/guomi/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/ZeroMarker/guomi/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ZeroMarker/guomi/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ZeroMarker/guomi/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ZeroMarker/guomi/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ZeroMarker/guomi/releases/tag/v0.1.0
