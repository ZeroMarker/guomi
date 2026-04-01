#!/bin/bash
#
# compare_with_openssl.sh
# Compare Guomi CLI tool output with OpenSSL for SM2/SM3/SM4 algorithms
#
# Usage: ./test/compare_with_openssl.sh
#
# Prerequisites:
#   - Built guomi binary (run: mix escript.build)
#   - OpenSSL 3.0+ with SM2/SM3/SM4 support
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
GUOMI_BIN="$PROJECT_DIR/guomi"
TEMP_DIR=$(mktemp -d)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Cleanup on exit
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Check prerequisites
check_prereqs() {
  local missing=0

  if [ ! -f "$GUOMI_BIN" ]; then
    echo -e "${RED}Error: guomi binary not found at $GUOMI_BIN${NC}"
    echo "Please run: mix escript.build"
    missing=1
  fi

  if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: openssl not found${NC}"
    missing=1
  fi

  if [ $missing -eq 1 ]; then
    exit 1
  fi
}

# Log test result
log_pass() {
  echo -e "${GREEN}[PASS]${NC} $1"
  ((TESTS_PASSED++))
}

log_fail() {
  echo -e "${RED}[FAIL]${NC} $1"
  ((TESTS_FAILED++))
}

log_skip() {
  echo -e "${YELLOW}[SKIP]${NC} $1"
  ((TESTS_SKIPPED++))
}

# Compare two hex strings
compare_hex() {
  local expected="$1"
  local actual="$2"
  local test_name="$3"

  if [ "${expected,,}" = "${actual,,}" ]; then
    log_pass "$test_name"
    return 0
  else
    log_fail "$test_name"
    echo "  Expected: $expected"
    echo "  Actual:   $actual"
    return 1
  fi
}

# =============================================================================
# SM3 Tests
# =============================================================================
test_sm3() {
  echo ""
  echo "=== SM3 Hash Tests ==="

  # Test 1: Empty string
  local input=""
  local guomi_result=$(echo -n "$input" | "$GUOMI_BIN" sm3 --hex)
  local openssl_result=$(echo -n "$input" | openssl sm3 -hex 2>/dev/null | awk '{print $NF}')
  compare_hex "$openssl_result" "$guomi_result" "SM3 empty string"

  # Test 2: Simple string
  input="abc"
  guomi_result=$(echo -n "$input" | "$GUOMI_BIN" sm3 --hex)
  openssl_result=$(echo -n "$input" | openssl sm3 -hex 2>/dev/null | awk '{print $NF}')
  compare_hex "$openssl_result" "$guomi_result" "SM3 'abc'"

  # Test 3: Hello World
  input="hello world"
  guomi_result=$(echo -n "$input" | "$GUOMI_BIN" sm3 --hex)
  openssl_result=$(echo -n "$input" | openssl sm3 -hex 2>/dev/null | awk '{print $NF}')
  compare_hex "$openssl_result" "$guomi_result" "SM3 'hello world'"

  # Test 4: Longer input
  input="The quick brown fox jumps over the lazy dog"
  guomi_result=$(echo -n "$input" | "$GUOMI_BIN" sm3 --hex)
  openssl_result=$(echo -n "$input" | openssl sm3 -hex 2>/dev/null | awk '{print $NF}')
  compare_hex "$openssl_result" "$guomi_result" "SM3 longer input"

  # Test 5: Binary data
  echo -ne '\x00\x01\x02\x03\xff\xfe' > "$TEMP_DIR/binary_data"
  guomi_result=$("$GUOMI_BIN" sm3 --hex "$TEMP_DIR/binary_data")
  openssl_result=$(openssl sm3 -hex "$TEMP_DIR/binary_data" 2>/dev/null | awk '{print $NF}')
  compare_hex "$openssl_result" "$guomi_result" "SM3 binary data"
}

# =============================================================================
# SM4 Tests
# =============================================================================
test_sm4() {
  echo ""
  echo "=== SM4 Cipher Tests ==="

  local key="0123456789abcdef0123456789abcdef"
  local iv="00112233445566778899aabbccddeeff"
  local plaintext="Hello, SM4!"

  # Test SM4-ECB Encryption
  echo ""
  echo "--- SM4-ECB ---"
  local guomi_enc=$(echo -n "$plaintext" | "$GUOMI_BIN" sm4 --key "$key" --hex 2>/dev/null | xxd -p | tr -d '\n')
  local openssl_enc=$(echo -n "$plaintext" | openssl sm4-ecb -K "$key" 2>/dev/null | xxd -p | tr -d '\n')
  compare_hex "$openssl_enc" "$guomi_enc" "SM4-ECB encrypt"

  # Test SM4-ECB Decryption
  local guomi_dec=$(echo "$guomi_enc" | xxd -r -p | "$GUOMI_BIN" sm4 --decrypt --key "$key" --hex 2>/dev/null)
  if [ "$guomi_dec" = "$plaintext" ]; then
    log_pass "SM4-ECB decrypt (self-test)"
  else
    log_fail "SM4-ECB decrypt (self-test)"
  fi

  # Test SM4-CBC Encryption
  echo ""
  echo "--- SM4-CBC ---"
  guomi_enc=$(echo -n "$plaintext" | "$GUOMI_BIN" sm4 --mode cbc --key "$key" --iv "$iv" --hex 2>/dev/null | xxd -p | tr -d '\n')
  openssl_enc=$(echo -n "$plaintext" | openssl sm4-cbc -K "$key" -iv "$iv" 2>/dev/null | xxd -p | tr -d '\n')
  compare_hex "$openssl_enc" "$guomi_enc" "SM4-CBC encrypt"

  # Test SM4-CBC Decryption
  guomi_dec=$(echo "$guomi_enc" | xxd -r -p | "$GUOMI_BIN" sm4 --decrypt --mode cbc --key "$key" --iv "$iv" --hex 2>/dev/null)
  if [ "$guomi_dec" = "$plaintext" ]; then
    log_pass "SM4-CBC decrypt (self-test)"
  else
    log_fail "SM4-CBC decrypt (self-test)"
  fi

  # Test with different plaintext
  plaintext="Test message for SM4 CBC mode verification"
  guomi_enc=$(echo -n "$plaintext" | "$GUOMI_BIN" sm4 --mode cbc --key "$key" --iv "$iv" --hex 2>/dev/null | xxd -p | tr -d '\n')
  openssl_enc=$(echo -n "$plaintext" | openssl sm4-cbc -K "$key" -iv "$iv" 2>/dev/null | xxd -p | tr -d '\n')
  compare_hex "$openssl_enc" "$guomi_enc" "SM4-CBC encrypt (longer text)"
}

# =============================================================================
# SM2 Tests
# =============================================================================
test_sm2() {
  echo ""
  echo "=== SM2 Asymmetric Tests ==="

  # Check if SM2 is supported by OpenSSL
  if ! openssl pkey -genpkey -algorithm EC -pkeyopt ec_paramgen_curve:SM2 &>/dev/null; then
    log_skip "SM2 tests (OpenSSL SM2 support not available)"
    return
  fi

  # Generate SM2 keypair with OpenSSL
  echo ""
  echo "--- Key Generation ---"
  openssl pkey -genpkey -algorithm EC -pkeyopt ec_paramgen_curve:SM2 -out "$TEMP_DIR/sm2_private.pem" 2>/dev/null
  openssl pkey -in "$TEMP_DIR/sm2_private.pem" -pubout -out "$TEMP_DIR/sm2_public.pem" 2>/dev/null

  # Extract raw keys
  local private_key=$(openssl pkey -in "$TEMP_DIR/sm2_private.pem" -outform DER 2>/dev/null | tail -c 32 | xxd -p | tr -d '\n')
  local public_key=$(openssl pkey -in "$TEMP_DIR/sm2_public.pem" -pubin -outform DER 2>/dev/null | xxd -p | tr -d '\n')

  # Test SM2 Sign/Verify
  echo ""
  echo "--- Sign/Verify ---"
  local message="Test message for SM2 signing"

  # Sign with OpenSSL
  echo -n "$message" | openssl pkeyutl -sign -inkey "$TEMP_DIR/sm2_private.pem" -out "$TEMP_DIR/signature.bin" 2>/dev/null
  local openssl_sig=$(xxd -p "$TEMP_DIR/signature.bin" | tr -d '\n')

  # Sign with Guomi
  local guomi_sig=$(echo -n "$message" | "$GUOMI_BIN" sm2 --sign --private-key "$private_key" 2>/dev/null)

  # Verify with OpenSSL
  if echo -n "$message" | openssl pkeyutl -verify -pubin -inkey "$TEMP_DIR/sm2_public.pem" -signature "$TEMP_DIR/signature.bin" &>/dev/null; then
    log_pass "SM2 OpenSSL verify (OpenSSL signature)"
  else
    log_fail "SM2 OpenSSL verify (OpenSSL signature)"
  fi

  # Verify with Guomi
  if echo -n "$message" | "$GUOMI_BIN" sm2 --verify --public-key "$public_key" --signature "$guomi_sig" &>/dev/null; then
    log_pass "SM2 Guomi verify (Guomi signature)"
  else
    log_fail "SM2 Guomi verify (Guomi signature)"
  fi

  # Test SM2 Encrypt/Decrypt
  echo ""
  echo "--- Encrypt/Decrypt ---"
  local plaintext="Secret message for SM2 encryption"

  # Encrypt with OpenSSL
  echo -n "$plaintext" | openssl pkeyutl -encrypt -pubin -inkey "$TEMP_DIR/sm2_public.pem" -out "$TEMP_DIR/ciphertext.bin" 2>/dev/null
  local openssl_ct=$(xxd -p "$TEMP_DIR/ciphertext.bin" | tr -d '\n')

  # Decrypt with Guomi (if supported)
  # Note: SM2 encryption format may differ between implementations
  log_skip "SM2 cross-encryption test (format differences)"
}

# =============================================================================
# Main
# =============================================================================
main() {
  echo "========================================"
  echo "Guomi vs OpenSSL Comparison Test"
  echo "========================================"
  echo ""

  check_prereqs

  echo "Guomi binary: $GUOMI_BIN"
  echo "OpenSSL version: $(openssl version)"
  echo "Temp directory: $TEMP_DIR"
  echo ""

  test_sm3
  test_sm4
  test_sm2

  echo ""
  echo "========================================"
  echo "Test Summary"
  echo "========================================"
  echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
  echo -e "${RED}Failed: $TESTS_FAILED${NC}"
  echo -e "${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
  echo ""

  if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
  else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
  fi
}

main "$@"
