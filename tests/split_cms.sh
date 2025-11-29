#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TEST_DIR="$(mktemp -d --tmpdir pkcs11_cms_test.XXXXXXXX)"
REPO_ROOT="$(realpath "$(dirname "$0")/..")"

mkdir -p "$TEST_DIR/api"
cp -r "$REPO_ROOT/api/"* "$TEST_DIR/api/"

# Function to run CMS sign and verify test
test_cms_sign_verify() {
    local key_type="$1"  # "ec", "ec_der", or "rsa"
    local cert_endpoint="$2"

    echo -e "${YELLOW}=== Testing ${key_type^^} key ===${NC}"

    # Configure shim for this key type
    case "$key_type" in
        "ec")
            export PKCS11_SHIM_API_CERT_GET_PATH="$cert_endpoint"
            export PKCS11_SHIM_API_SIGN_PATH="/sign_ec"
            ;;
        "ec_der")
            export PKCS11_SHIM_API_CERT_GET_PATH="$cert_endpoint"
            export PKCS11_SHIM_API_SIGN_PATH="/sign_ec_der"
            ;;
        "rsa")
            export PKCS11_SHIM_API_CERT_GET_PATH="$cert_endpoint"
            export PKCS11_SHIM_API_SIGN_PATH="/sign_rsa"
            ;;
    esac

    # Fetch certificate from API and convert to PEM
    local cert_file="$TEST_DIR/cert_${key_type}.pem"
    curl -s -H "X-Auth-Token:secret123" "http://localhost:27180${cert_endpoint}" | \
        jq -r '.certificate' | base64 -d | \
        openssl x509 -inform DER -out "$cert_file"

    local sig_file="$TEST_DIR/data.signed.${key_type}"

    # Sign
    echo "Signing with ${key_type^^}..."
    KEY_URI="pkcs11:token=Shim%20Token;object=Shim%20Key;type=private"
    openssl cms -sign -binary -md sha512 \
        -in "$TEST_DIR/data.txt" -out "$sig_file" -outform DER \
        -provider-path "$REPO_ROOT/build/src" -provider pkcs11 -provider default \
        -inkey "$KEY_URI" -signer "$cert_file"

    # Print CMS structure
    echo "CMS structure:"
    openssl cms -binary -cmsout -print -inform DER -in "$sig_file" | head -30

    # Verify
    echo "Verifying ${key_type^^} signature..."
    openssl cms -verify -content "$TEST_DIR/data.txt" -binary -inform DER \
        -in "$sig_file" -CAfile "$cert_file" -noverify -out /dev/null

    echo -e "${GREEN}${key_type^^} test passed!${NC}"
    echo

    # Cleanup signature file
    rm -f "$sig_file" "$cert_file"
}

# Generate EC certificate
echo "Generating EC certificate..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$TEST_DIR/api/ec_private_key.pem"
openssl req -new -x509 -days 365 -key "$TEST_DIR/api/ec_private_key.pem" -out "$TEST_DIR/api/ec_cert.pem" -subj "/CN=Test EC Signer"

# Generate RSA certificate
echo "Generating RSA certificate..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TEST_DIR/api/rsa_private_key.pem"
openssl req -new -x509 -days 365 -key "$TEST_DIR/api/rsa_private_key.pem" -out "$TEST_DIR/api/rsa_cert.pem" -subj "/CN=Test RSA Signer"

# Start API server
echo "Starting API server..."
cd "$TEST_DIR/api"
go build -o api_server
export PKCS11_SHIM_AUTH="X-Auth-Token:secret123"
./api_server &
API_PID=$!
cd ..

cleanup() {
    echo "Cleaning up..."
    if [ -n "$API_PID" ]; then
        kill "$API_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup ERR HUP INT QUIT TERM PWR EXIT

# Wait for API to start
sleep 2

# Create data to sign
echo "Hello, World!" > "$TEST_DIR/data.txt"

# Common environment variables
export PKCS11_SHIM_URL="http://localhost:27180"
export PKCS11_PROVIDER_MODULE="/usr/lib64/pkcs11/p11-kit-proxy.so"
export PKCS11_PROVIDER_DEBUG="file:/dev/stderr"
export PKCS11_SHIM_AUTH="X-Auth-Token:secret123"
export PKCS11_SHIM_API_SIGN_REQUEST_FORMAT='{"hash": "%s"}'
export PKCS11_SHIM_DEBUG="file:/dev/stderr"

# Run tests for all key types
test_cms_sign_verify "ec" "/cert_ec"
test_cms_sign_verify "ec_der" "/cert_ec" 
test_cms_sign_verify "rsa" "/cert_rsa"

echo -e "${GREEN}All tests passed!${NC}"
