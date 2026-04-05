# Changelog

All notable changes to Guomi will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CLI tool with commands for SM2, SM3, and SM4 operations
- `Guomi.CLI` module for command-line interface
- Version and help commands for CLI

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [0.3.0] - 2026-04-05

### Added
- CLI tool with commands for SM2, SM3, and SM4 operations
- `Guomi.CLI` module for command-line interface
- Version and help commands for CLI

## [0.2.0] - 2026-04-01

### Added
- SM2 encryption and decryption functionality
- `Guomi.SM2.encrypt/2` and `Guomi.SM2.decrypt/2` functions

### Changed
- Updated version to 0.2.0

## [0.1.0] - 2026-03-28

### Added
- Initial release
- SM2 implementation:
  - Key pair generation
  - Signing and verification
  - Encryption and decryption
- SM3 implementation:
  - Hash function with binary output
  - Hash function with hexadecimal output
- SM4 implementation:
  - ECB mode encryption/decryption
  - CBC mode encryption/decryption
  - PKCS7 and none padding support
- Runtime support detection for all algorithms
- Comprehensive test suite
- Documentation with ExDoc

[Unreleased]: https://github.com/ZeroMarker/guomi/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ZeroMarker/guomi/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ZeroMarker/guomi/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ZeroMarker/guomi/releases/tag/v0.1.0
