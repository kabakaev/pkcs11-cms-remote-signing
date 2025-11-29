#!/bin/bash
set -e

# Generate self-signed certificate
echo "Generating certificate..."
# Generate self-signed certificate
echo "Generating certificate..."
rm -f api/private_key.pem api/public_key.pem cert.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out api/private_key.pem
openssl req -new -x509 -days 365 -key api/private_key.pem -out api/public_key.pem -subj "/CN=Test Signer"
cp api/public_key.pem cert.pem

# Kill any existing API server
pkill -f api_server || true

# Start API server
echo "Starting API server..."
cd api
go build -o api_server
export PKCS11_SHIM_AUTH="X-Auth-Token:secret123"
./api_server &
API_PID=$!
cd ..

# Wait for API to start and generate keys
sleep 2

# Create data to sign
echo "Creating data to sign..."
echo "Hello, World!" > data.txt

# Create openssl config
cat > openssl.cnf <<EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = $(pwd)/build/src/pkcs11.so
pkcs11-module-path = /usr/lib64/pkcs11/p11-kit-proxy.so
activate = 1
EOF

# Sign
echo "Signing..."
export PKCS11_SHIM_URL="http://localhost:42180"
export PKCS11_PROVIDER_MODULE="/usr/lib64/pkcs11/p11-kit-proxy.so"
export PKCS11_PROVIDER_DEBUG="file:/dev/stderr"
export PKCS11_SHIM_AUTH="X-Auth-Token:secret123"
export PKCS11_SHIM_PAYLOAD_FORMAT="{\"file\": \"%s\", \"mechanism\": \"ECDSA\"}"
export PKCS11_SHIM_DEBUG="file:/dev/stderr"

# We need to specify the key. The shim returns a key with ID 01 and label "Shim Key".
# We can use a PKCS#11 URI.
# slot-id=1, object-label=Shim Key
KEY_URI="pkcs11:token=Shim%20Token;object=Shim%20Key;type=private"

openssl cms -sign -binary -md sha512 -in data.txt -out data.signed -outform DER -provider-path $(pwd)/build/src -provider pkcs11 -provider default -inkey "$KEY_URI" -signer cert.pem

# Verify
echo "Verifying..."
# Unset PKCS11 env vars to ensure we verify using default provider/config
unset PKCS11_SHIM_URL
unset PKCS11_PROVIDER_MODULE
unset PKCS11_PROVIDER_DEBUG

openssl cms -binary -cmsout -print -inform DER -in data.signed

# We need the public key/cert. cert.pem is the certificate.
openssl cms -verify -content data.txt -binary -inform DER -in data.signed -CAfile cert.pem -noverify -out /dev/null

echo "Success!"

# Cleanup
kill $API_PID

#echo "press Enter to delete temp files"
#read

rm data.txt data.signed openssl.cnf cert.pem api/api_server api/private_key.pem api/public_key.pem
