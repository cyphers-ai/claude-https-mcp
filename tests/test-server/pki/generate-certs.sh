#!/bin/bash
# n8n-https Test PKI Generator
# Generates a complete PKI infrastructure for testing TLS features

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="$SCRIPT_DIR"

# Configuration
DAYS_VALID=365
DAYS_CA=3650
KEY_SIZE=2048
CA_KEY_SIZE=4096

# Custom IP for remote deployment (set via environment variable)
# Usage: TEST_SERVER_IP=192.168.1.100 ./generate-certs.sh
SERVER_IP="${TEST_SERVER_IP:-127.0.0.1}"
SERVER_HOSTNAME="${TEST_SERVER_HOSTNAME:-localhost}"

# Build SAN string
SAN_STRING="DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

# Add custom hostname if different from localhost
if [ "$SERVER_HOSTNAME" != "localhost" ]; then
    SAN_STRING="$SAN_STRING,DNS:$SERVER_HOSTNAME"
fi

# Add custom IP if different from 127.0.0.1
if [ "$SERVER_IP" != "127.0.0.1" ]; then
    SAN_STRING="$SAN_STRING,IP:$SERVER_IP"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[+]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Check for required tools
check_requirements() {
    if ! command -v openssl &> /dev/null; then
        error "openssl is required but not installed"
    fi

    OPENSSL_VERSION=$(openssl version)
    info "Using: $OPENSSL_VERSION"
}

# Create directory structure
create_dirs() {
    log "Creating directory structure..."
    mkdir -p "$PKI_DIR"/{root-ca,intermediate-ca,server-certs/{valid,expired,revoked,selfsigned,wronghost},client-certs,crl}
}

# Generate Root CA
generate_root_ca() {
    log "Generating Root CA..."

    local dir="$PKI_DIR/root-ca"

    # Generate private key
    openssl genrsa -out "$dir/root-ca.key" $CA_KEY_SIZE 2>/dev/null
    chmod 400 "$dir/root-ca.key"

    # Create config for Root CA
    cat > "$dir/root-ca.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = US
ST = Test State
L = Test City
O = n8n-https Test
OU = Test PKI
CN = Test Root CA

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF

    # Generate self-signed certificate
    openssl req -x509 -new -nodes \
        -key "$dir/root-ca.key" \
        -sha256 -days $DAYS_CA \
        -out "$dir/root-ca.crt" \
        -config "$dir/root-ca.cnf"

    log "Root CA created: $dir/root-ca.crt"
}

# Generate Intermediate CA
generate_intermediate_ca() {
    log "Generating Intermediate CA..."

    local dir="$PKI_DIR/intermediate-ca"
    local root_dir="$PKI_DIR/root-ca"

    # Generate private key
    openssl genrsa -out "$dir/intermediate-ca.key" $CA_KEY_SIZE 2>/dev/null
    chmod 400 "$dir/intermediate-ca.key"

    # Create config for Intermediate CA
    cat > "$dir/intermediate-ca.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
C = US
ST = Test State
L = Test City
O = n8n-https Test
OU = Test PKI
CN = Test Intermediate CA

[v3_intermediate_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ca]
default_ca = CA_default

[CA_default]
dir               = $dir
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
certificate       = \$dir/intermediate-ca.crt
private_key       = \$dir/intermediate-ca.key
default_md        = sha256
default_days      = 365
default_crl_days  = 30
crl               = \$dir/crl.pem
policy            = policy_loose
copy_extensions   = copy

[policy_loose]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[server_cert]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "Test Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[client_cert]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "Test Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EOF

    # Generate CSR
    openssl req -new \
        -key "$dir/intermediate-ca.key" \
        -out "$dir/intermediate-ca.csr" \
        -config "$dir/intermediate-ca.cnf"

    # Sign with Root CA
    openssl x509 -req \
        -in "$dir/intermediate-ca.csr" \
        -CA "$root_dir/root-ca.crt" \
        -CAkey "$root_dir/root-ca.key" \
        -CAcreateserial \
        -out "$dir/intermediate-ca.crt" \
        -days 1825 -sha256 \
        -extfile "$dir/intermediate-ca.cnf" \
        -extensions v3_intermediate_ca

    # Initialize CA database
    mkdir -p "$dir/newcerts"
    touch "$dir/index.txt"
    echo "1000" > "$dir/serial"
    echo "1000" > "$dir/crlnumber"

    log "Intermediate CA created: $dir/intermediate-ca.crt"
}

# Generate a server certificate
generate_server_cert() {
    local name=$1
    local cn=$2
    local san=$3
    local days=${4:-$DAYS_VALID}
    local dir="$PKI_DIR/server-certs/$name"
    local ca_dir="$PKI_DIR/intermediate-ca"

    log "Generating $name server certificate (CN=$cn)..."

    # Generate private key
    openssl genrsa -out "$dir/server.key" $KEY_SIZE 2>/dev/null
    chmod 400 "$dir/server.key"

    # Create config with SAN
    cat > "$dir/server.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
C = US
ST = Test State
L = Test City
O = n8n-https Test
CN = $cn

[req_ext]
subjectAltName = $san

[server_cert]
basicConstraints = CA:FALSE
nsCertType = server
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $san
EOF

    # Generate CSR
    openssl req -new \
        -key "$dir/server.key" \
        -out "$dir/server.csr" \
        -config "$dir/server.cnf"

    # Sign with Intermediate CA
    openssl x509 -req \
        -in "$dir/server.csr" \
        -CA "$ca_dir/intermediate-ca.crt" \
        -CAkey "$ca_dir/intermediate-ca.key" \
        -CAserial "$ca_dir/serial" \
        -out "$dir/server.crt" \
        -days "$days" -sha256 \
        -extfile "$dir/server.cnf" \
        -extensions server_cert

    # Create full chain (server + intermediate)
    cat "$dir/server.crt" "$ca_dir/intermediate-ca.crt" > "$dir/fullchain.crt"

    log "$name certificate created: $dir/server.crt"
}

# Generate self-signed certificate (not trusted by our CA)
generate_selfsigned_cert() {
    log "Generating self-signed certificate..."
    local dir="$PKI_DIR/server-certs/selfsigned"

    openssl req -x509 -nodes -newkey rsa:$KEY_SIZE \
        -keyout "$dir/server.key" \
        -out "$dir/server.crt" \
        -days $DAYS_VALID \
        -subj "/C=US/ST=Test/L=Test/O=Self-Signed Inc/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        2>/dev/null

    chmod 400 "$dir/server.key"
    cp "$dir/server.crt" "$dir/fullchain.crt"

    log "Self-signed certificate created"
}

# Generate expired certificate
generate_expired_cert() {
    log "Generating expired certificate..."
    local dir="$PKI_DIR/server-certs/expired"
    local ca_dir="$PKI_DIR/intermediate-ca"

    # Generate private key
    openssl genrsa -out "$dir/server.key" $KEY_SIZE 2>/dev/null
    chmod 400 "$dir/server.key"

    # Create config
    cat > "$dir/server.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
C = US
ST = Test State
L = Test City
O = n8n-https Test
CN = localhost

[server_cert]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
EOF

    # Generate CSR
    openssl req -new \
        -key "$dir/server.key" \
        -out "$dir/server.csr" \
        -config "$dir/server.cnf"

    # Create a certificate that's already expired
    # We'll set start date in the past and a short validity
    # Using -startdate and -enddate for precise control

    # Get dates: started 2 days ago, ended 1 day ago
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        START_DATE=$(date -v-2d +%y%m%d%H%M%SZ)
        END_DATE=$(date -v-1d +%y%m%d%H%M%SZ)
    else
        # Linux
        START_DATE=$(date -d "-2 days" +%y%m%d%H%M%SZ)
        END_DATE=$(date -d "-1 day" +%y%m%d%H%M%SZ)
    fi

    # Sign with specific dates to make it expired
    openssl ca -batch \
        -config "$ca_dir/intermediate-ca.cnf" \
        -startdate "$START_DATE" \
        -enddate "$END_DATE" \
        -notext -md sha256 \
        -in "$dir/server.csr" \
        -out "$dir/server.crt" \
        -extensions server_cert \
        -extfile "$dir/server.cnf" \
        2>/dev/null || {
            # Fallback: create with -days 0 (not ideal but works)
            warn "Using fallback method for expired cert"
            openssl x509 -req \
                -in "$dir/server.csr" \
                -CA "$ca_dir/intermediate-ca.crt" \
                -CAkey "$ca_dir/intermediate-ca.key" \
                -CAserial "$ca_dir/serial" \
                -out "$dir/server.crt" \
                -days 0 -sha256 \
                -extfile "$dir/server.cnf" \
                -extensions server_cert
        }

    cat "$dir/server.crt" "$ca_dir/intermediate-ca.crt" > "$dir/fullchain.crt"
    log "Expired certificate created"
}

# Generate client certificates for mTLS
generate_client_certs() {
    log "Generating client certificates..."
    local dir="$PKI_DIR/client-certs"
    local ca_dir="$PKI_DIR/intermediate-ca"

    # Valid client cert
    openssl genrsa -out "$dir/valid-client.key" $KEY_SIZE 2>/dev/null
    chmod 400 "$dir/valid-client.key"

    cat > "$dir/client.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
C = US
ST = Test State
L = Test City
O = n8n-https Test
CN = Test Client

[client_cert]
basicConstraints = CA:FALSE
nsCertType = client
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EOF

    openssl req -new \
        -key "$dir/valid-client.key" \
        -out "$dir/valid-client.csr" \
        -config "$dir/client.cnf"

    openssl x509 -req \
        -in "$dir/valid-client.csr" \
        -CA "$ca_dir/intermediate-ca.crt" \
        -CAkey "$ca_dir/intermediate-ca.key" \
        -CAserial "$ca_dir/serial" \
        -out "$dir/valid-client.crt" \
        -days $DAYS_VALID -sha256 \
        -extfile "$dir/client.cnf" \
        -extensions client_cert

    # Create PKCS#12 bundle (for easy import)
    openssl pkcs12 -export \
        -out "$dir/valid-client.p12" \
        -inkey "$dir/valid-client.key" \
        -in "$dir/valid-client.crt" \
        -certfile "$ca_dir/intermediate-ca.crt" \
        -passout pass:testpassword

    # Create combined PEM (cert + key in one file)
    cat "$dir/valid-client.crt" "$dir/valid-client.key" > "$dir/valid-client-combined.pem"
    chmod 400 "$dir/valid-client-combined.pem"

    log "Client certificates created"
    info "PKCS#12 password: testpassword"
}

# Generate CA bundle
generate_ca_bundle() {
    log "Generating CA bundle..."
    cat "$PKI_DIR/intermediate-ca/intermediate-ca.crt" "$PKI_DIR/root-ca/root-ca.crt" > "$PKI_DIR/ca-bundle.crt"
    log "CA bundle created: $PKI_DIR/ca-bundle.crt"
}

# Revoke a certificate and generate CRL
generate_crl() {
    log "Setting up certificate revocation..."
    local ca_dir="$PKI_DIR/intermediate-ca"
    local revoked_dir="$PKI_DIR/server-certs/revoked"

    # First, we need to issue a certificate to revoke
    if [ ! -f "$revoked_dir/server.crt" ]; then
        generate_server_cert "revoked" "localhost" "DNS:localhost,IP:127.0.0.1"
    fi

    # Revoke it
    openssl ca -batch \
        -config "$ca_dir/intermediate-ca.cnf" \
        -revoke "$revoked_dir/server.crt" \
        2>/dev/null || warn "Certificate may already be revoked"

    # Generate CRL
    openssl ca -batch \
        -config "$ca_dir/intermediate-ca.cnf" \
        -gencrl \
        -out "$PKI_DIR/crl/revoked.crl"

    # Also create DER format
    openssl crl \
        -in "$PKI_DIR/crl/revoked.crl" \
        -outform DER \
        -out "$PKI_DIR/crl/revoked.crl.der"

    log "CRL generated: $PKI_DIR/crl/revoked.crl"
}

# Print summary of generated certificates
print_summary() {
    echo ""
    echo "========================================"
    echo "  PKI Generation Complete!"
    echo "========================================"
    echo ""
    echo "Root CA:"
    openssl x509 -in "$PKI_DIR/root-ca/root-ca.crt" -noout -subject -dates 2>/dev/null | head -3
    echo ""
    echo "Intermediate CA:"
    openssl x509 -in "$PKI_DIR/intermediate-ca/intermediate-ca.crt" -noout -subject -dates 2>/dev/null | head -3
    echo ""
    echo "Server Certificates:"
    for cert in "$PKI_DIR"/server-certs/*/server.crt; do
        if [ -f "$cert" ]; then
            dir=$(dirname "$cert")
            name=$(basename "$dir")
            echo "  - $name:"
            openssl x509 -in "$cert" -noout -subject -enddate 2>/dev/null | sed 's/^/      /'
        fi
    done
    echo ""
    echo "Client Certificate:"
    openssl x509 -in "$PKI_DIR/client-certs/valid-client.crt" -noout -subject -dates 2>/dev/null | head -3
    echo ""
    echo "Files:"
    echo "  CA Bundle:     $PKI_DIR/ca-bundle.crt"
    echo "  Client P12:    $PKI_DIR/client-certs/valid-client.p12 (password: testpassword)"
    echo "  CRL:           $PKI_DIR/crl/revoked.crl"
    echo ""
}

# Compute SPKI hash for pinning tests
compute_spki_hash() {
    local cert=$1
    openssl x509 -in "$cert" -pubkey -noout 2>/dev/null | \
        openssl pkey -pubin -outform DER 2>/dev/null | \
        openssl dgst -sha256 -binary | \
        openssl enc -base64
}

# Generate pinning file with SPKI hashes
generate_pinning_file() {
    log "Generating SPKI hashes for certificate pinning..."

    local pin_file="$PKI_DIR/pinning-hashes.txt"

    echo "# SPKI Hashes for Certificate Pinning" > "$pin_file"
    echo "# Generated: $(date)" >> "$pin_file"
    echo "" >> "$pin_file"

    for cert in "$PKI_DIR"/server-certs/valid/server.crt \
                "$PKI_DIR"/intermediate-ca/intermediate-ca.crt \
                "$PKI_DIR"/root-ca/root-ca.crt; do
        if [ -f "$cert" ]; then
            name=$(basename "$(dirname "$cert")")
            hash=$(compute_spki_hash "$cert")
            echo "# $name" >> "$pin_file"
            echo "sha256/$hash" >> "$pin_file"
            echo "" >> "$pin_file"
        fi
    done

    log "Pinning hashes saved to: $pin_file"
}

# Main
main() {
    echo ""
    echo "========================================"
    echo "  n8n-https Test PKI Generator"
    echo "========================================"
    echo ""

    check_requirements
    create_dirs

    # Display configuration
    info "Server IP: $SERVER_IP"
    info "Server Hostname: $SERVER_HOSTNAME"
    info "SAN: $SAN_STRING"
    echo ""

    # Generate CA hierarchy
    generate_root_ca
    generate_intermediate_ca
    generate_ca_bundle

    # Generate server certificates
    generate_server_cert "valid" "localhost" "$SAN_STRING"
    generate_server_cert "wronghost" "wronghost.example.com" "DNS:wronghost.example.com,DNS:*.wronghost.example.com"
    generate_selfsigned_cert
    generate_expired_cert

    # Generate CRL (this also creates the revoked cert)
    generate_crl

    # Generate client certificates
    generate_client_certs

    # Generate pinning hashes
    generate_pinning_file

    print_summary
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
