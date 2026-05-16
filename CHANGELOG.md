# Changelog

All notable changes to Guomi are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/ZeroMarker/guomi/compare/v0.4.2...HEAD
[0.4.2]: https://github.com/ZeroMarker/guomi/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/ZeroMarker/guomi/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ZeroMarker/guomi/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ZeroMarker/guomi/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ZeroMarker/guomi/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ZeroMarker/guomi/releases/tag/v0.1.0
