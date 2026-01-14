#!/bin/bash

# Simple script to generate a CA certificate/private key
# and end-entity certificate/private key for use with 
# Roles Anywhere, plus ML-DSA test fixtures

set -exuo pipefail

script=$(readlink -f "$0")
basedir=$(dirname "$script")
data_folder=${basedir}/credential-process-data
cert_dir=${basedir}/tst/certs

# Create directories if they don't exist
mkdir -p ${data_folder}
mkdir -p ${cert_dir}

# Create root CA config file
cat > ${data_folder}/root.conf << EOF
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
CN = TEST ROOT

[ v3 ]
basicConstraints = critical,CA:TRUE,pathlen:1
subjectKeyIdentifier = hash
keyUsage = critical, cRLSign, digitalSignature, keyCertSign
authorityKeyIdentifier = keyid:always,issuer:always
EOF

# Create root CA certificate and RSA private key
openssl req -config ${data_folder}/root.conf -days 365 -extensions v3 -keyout ${data_folder}/root-key.pem -newkey rsa:2048 -nodes -out ${data_folder}/root-cert.pem -set_serial 1 -sha256 -x509

# Create client certificate config file
cat > ${data_folder}/client.conf <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt = no
default_bits = 2048
default_md = sha256

[ req_distinguished_name ]
CN = TEST CLIENT

[ v3 ]
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
EOF

# Create client certificate and RSA private key
openssl req -nodes -new -keyout ${data_folder}/client-key.pem -out ${data_folder}/client-csr.pem -config ${data_folder}/client.conf
openssl x509 -req -in ${data_folder}/client-csr.pem -CA ${data_folder}/root-cert.pem -CAkey ${data_folder}/root-key.pem -set_serial 2 -out ${data_folder}/client-cert.pem -days 365 -sha256 -extfile ${data_folder}/client.conf -extensions v3

# Generate ML-DSA test fixtures
echo "Generating ML-DSA test fixtures..."

# Password for encrypted keys
PASSWORD="password"

# ML-DSA variants
MLDSA_VARIANTS=("mldsa44" "mldsa65" "mldsa87")

# Encryption methods to test
ENCRYPTION_METHODS=(
    "aes128cbc"
    "aes192cbc" 
    "aes256cbc"
    "hmacWithSHA256"
    "hmacWithSHA384"
    "hmacWithSHA512"
    "scrypt"
)

# Function to get ML-DSA algorithm name
get_mldsa_algorithm() {
    local variant=$1
    case $variant in
        "mldsa44") echo "ML-DSA-44" ;;
        "mldsa65") echo "ML-DSA-65" ;;
        "mldsa87") echo "ML-DSA-87" ;;
        *) echo "Unknown" ;;
    esac
}

# Function to check if OpenSSL supports ML-DSA
check_mldsa_support() {
    # Try to generate a test ML-DSA key to check support
    if openssl genpkey -algorithm ML-DSA-44 -out /tmp/test_mldsa.pem 2>/dev/null; then
        rm -f /tmp/test_mldsa.pem
        return 0
    else
        return 1
    fi
}

# Function to generate ML-DSA private key and certificate
generate_mldsa_key_and_cert() {
    local variant=$1
    local algorithm=$(get_mldsa_algorithm "$variant")
    
    echo "Generating ML-DSA key and certificate for $variant ($algorithm)..."
    
    # Generate private key
    local key_file="${cert_dir}/${variant}-key.pem"
    local cert_file="${cert_dir}/${variant}-cert.pem"
    local pkcs8_key_file="${cert_dir}/${variant}-key-pkcs8.pem"
    
    # Try to generate ML-DSA key (this may fail if OpenSSL doesn't support ML-DSA)
    if openssl genpkey -algorithm "$algorithm" -out "$key_file" 2>/dev/null; then
        echo "Generated $key_file"
        
        # Convert to PKCS#8 format
        openssl pkey -in "$key_file" -out "$pkcs8_key_file"
        echo "Generated $pkcs8_key_file"
        
        # Generate self-signed certificate
        openssl req -new -x509 -key "$key_file" -out "$cert_file" -days 365 \
            -subj "/CN=Test ML-DSA $variant Certificate" 2>/dev/null || {
            echo "Warning: Failed to generate certificate for $variant"
            # Create a dummy certificate file for testing
            cat > "$cert_file" << EOF
-----BEGIN CERTIFICATE-----
# Dummy ML-DSA $variant certificate for testing
# This is not a real certificate
-----END CERTIFICATE-----
EOF
        }
        echo "Generated $cert_file"
        
        # Generate encrypted variants
        for method in "${ENCRYPTION_METHODS[@]}"; do
            local encrypted_key="${cert_dir}/${variant}-key-pkcs8-${method}.pem"
            
            case $method in
                aes128cbc)
                    cipher="-aes128"
                    ;;
                aes192cbc)
                    cipher="-aes192"
                    ;;
                aes256cbc)
                    cipher="-aes256"
                    ;;
                hmacWithSHA256)
                    cipher="-aes256 -v2 prf:hmacWithSHA256"
                    ;;
                hmacWithSHA384)
                    cipher="-aes256 -v2 prf:hmacWithSHA384"
                    ;;
                hmacWithSHA512)
                    cipher="-aes256 -v2 prf:hmacWithSHA512"
                    ;;
                scrypt)
                    cipher="-aes256 -scrypt"
                    ;;
            esac
            
            # Encrypt the PKCS#8 key
            if openssl pkey -in "$pkcs8_key_file" -out "$encrypted_key" $cipher -passout "pass:$PASSWORD" 2>/dev/null; then
                echo "Generated encrypted key: $encrypted_key"
            else
                echo "Warning: Failed to generate encrypted key with $method for $variant"
                # Create a dummy encrypted key file for testing
                cat > "$encrypted_key" << EOF
-----BEGIN ENCRYPTED PRIVATE KEY-----
# Dummy encrypted ML-DSA $variant key for testing ($method)
# This is not a real encrypted key
-----END ENCRYPTED PRIVATE KEY-----
EOF
            fi
        done
        
    else
        echo "Warning: Failed to generate ML-DSA key for $variant - OpenSSL may not support ML-DSA"
        echo "Creating dummy files for testing..."
        
        # Create dummy files for testing when ML-DSA is not supported
        cat > "$key_file" << EOF
-----BEGIN PRIVATE KEY-----
# Dummy ML-DSA $variant private key for testing
# This is not a real private key
-----END PRIVATE KEY-----
EOF
        
        cp "$key_file" "$pkcs8_key_file"
        
        cat > "$cert_file" << EOF
-----BEGIN CERTIFICATE-----
# Dummy ML-DSA $variant certificate for testing
# This is not a real certificate
-----END CERTIFICATE-----
EOF
        
        # Create dummy encrypted keys
        for method in "${ENCRYPTION_METHODS[@]}"; do
            local encrypted_key="${cert_dir}/${variant}-key-pkcs8-${method}.pem"
            cat > "$encrypted_key" << EOF
-----BEGIN ENCRYPTED PRIVATE KEY-----
# Dummy encrypted ML-DSA $variant key for testing ($method)
# This is not a real encrypted key
-----END ENCRYPTED PRIVATE KEY-----
EOF
        done
    fi
}

# Check ML-DSA support
if check_mldsa_support; then
    echo "OpenSSL supports ML-DSA - generating real ML-DSA fixtures"
    MLDSA_SUPPORTED=true
else
    echo "OpenSSL does not support ML-DSA - generating dummy fixtures for testing"
    MLDSA_SUPPORTED=false
fi

# Generate ML-DSA test fixtures for all variants
for variant in "${MLDSA_VARIANTS[@]}"; do
    generate_mldsa_key_and_cert "$variant"
done

echo "ML-DSA test fixture generation complete!"
echo "Generated files in: $cert_dir"
echo ""
if [ "$MLDSA_SUPPORTED" = true ]; then
    echo "Real ML-DSA keys and certificates were generated."
    echo "AES-CBC encryption methods should work."
    echo "HMAC and scrypt methods may have created dummy files if not supported."
else
    echo "Dummy ML-DSA files were created for testing."
    echo "The unit tests will skip tests for dummy fixtures."
fi
# Create invalid test files for negative testing
echo "Creating invalid test files for negative testing..."

# Invalid RSA certificate (for existing tests) - valid PEM structure but invalid certificate ASN.1 data
cat > ${cert_dir}/invalid-rsa-cert.pem << 'EOF'
-----BEGIN CERTIFICATE-----
MIICdTCCAd4CAQAwDQYJKoZIhvcNAQEFBQAwgYkxCzAJBgNVBAYTAlVTMQswCQYD
VQQIDAJDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEQMA4GA1UECgwHQ29tcGFu
eTEQMA4GA1UECwwHU2VjdGlvbjEQMA4GA1UEAwwHdGVzdC5jb20xHzAdBgkqhkiG
9w0BCQEWEHRlc3RAZXhhbXBsZS5jb20wHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAx
MDAwMDAwWjCBiTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1T
YW4gRnJhbmNpc2NvMRAwDgYDVQQKDAdDb21wYW55MRAwDgYDVQQLDAdTZWN0aW9u
MRAwDgYDVQQDDAd0ZXN0LmNvbTEfMB0GCSqGSIb3DQEJARYQdGVzdEBleGFtcGxl
LmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1234567890abcdefghij
klmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmn
opqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqr
stuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuv
wxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz
-----END CERTIFICATE-----
EOF

# Invalid RSA key (for existing tests) - valid PEM structure but invalid key data  
cat > ${cert_dir}/invalid-rsa-key.pem << 'EOF'
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1234567890INVALID_KEY_DATA
-----END PRIVATE KEY-----
EOF

# Verify ML-DSA fixtures were created
echo "Verifying ML-DSA fixtures..."
for variant in "${MLDSA_VARIANTS[@]}"; do
    key_file="${cert_dir}/${variant}-key-pkcs8.pem"
    cert_file="${cert_dir}/${variant}-cert.pem"
    
    if [ -f "$key_file" ] && [ -f "$cert_file" ]; then
        echo "✓ $variant fixtures created successfully"
        
        # Count encrypted variants
        encrypted_count=$(ls ${cert_dir}/${variant}-key-pkcs8-*.pem 2>/dev/null | wc -l)
        echo "  - $encrypted_count encrypted key variants created"
    else
        echo "✗ $variant fixtures missing"
    fi
done

echo ""
echo "Fixture generation summary:"
echo "- Credential process data: ${data_folder}/"
echo "- Test certificates and keys: ${cert_dir}/"
echo "- ML-DSA variants: ${#MLDSA_VARIANTS[@]} (mldsa44, mldsa65, mldsa87)"
echo "- Encryption methods per variant: ${#ENCRYPTION_METHODS[@]}"
echo "- Total ML-DSA files created: $(ls ${cert_dir}/mldsa* 2>/dev/null | wc -l)"