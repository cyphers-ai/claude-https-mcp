#!/bin/bash
# OCSP Responder startup script

set -e

PKI_DIR="/pki"
CA_DIR="$PKI_DIR/intermediate-ca"

echo "Starting OCSP Responder..."
echo "  Index: $CA_DIR/index.txt"
echo "  CA Cert: $CA_DIR/intermediate-ca.crt"
echo "  Port: 8888"
echo ""

# Check required files exist
if [ ! -f "$CA_DIR/index.txt" ]; then
    echo "ERROR: CA index file not found: $CA_DIR/index.txt"
    echo "Make sure to run 'make certs' first"
    exit 1
fi

if [ ! -f "$CA_DIR/intermediate-ca.crt" ]; then
    echo "ERROR: CA certificate not found: $CA_DIR/intermediate-ca.crt"
    exit 1
fi

if [ ! -f "$CA_DIR/intermediate-ca.key" ]; then
    echo "ERROR: CA key not found: $CA_DIR/intermediate-ca.key"
    exit 1
fi

# Start OCSP responder
# -index: Certificate database
# -port: Listen port
# -rsigner: Certificate to sign responses
# -rkey: Key to sign responses
# -CA: CA certificate (for chain)
# -text: Output text format
# -ignore_err: Continue on errors

exec openssl ocsp \
    -index "$CA_DIR/index.txt" \
    -port 8888 \
    -rsigner "$CA_DIR/intermediate-ca.crt" \
    -rkey "$CA_DIR/intermediate-ca.key" \
    -CA "$PKI_DIR/ca-bundle.crt" \
    -text \
    -ignore_err
