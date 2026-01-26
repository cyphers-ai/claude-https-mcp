# claude-https Test Server

A comprehensive test environment for testing the SecureWebFetch MCP tool with various TLS configurations.

## Quick Start (Local)

```bash
# Generate certificates and start all services
make start

# Run connectivity tests
make test

# View logs
make logs

# Stop everything
make stop
```

## Test Endpoints

| Port | Description | Expected Behavior | Tests |
|------|-------------|-------------------|-------|
| 9080 | HTTP (no TLS) | Success | Baseline, protocol handling |
| 9443 | TLS 1.3 only | Success with TLS 1.3 | Modern TLS negotiation, custom cipher strings |
| 9444 | TLS 1.2 only | Success with TLS 1.2 | Legacy TLS fallback |
| 9445 | mTLS required | Success with client cert | Client certificate auth (PEM and PKCS#12) |
| 9446 | Expired cert | **FAIL**: EHTTPS_CERT_EXPIRED | Expiration handling |
| 9447 | Self-signed | **FAIL**: EHTTPS_CERT_VERIFY | Trust chain validation |
| 9448 | Wrong hostname | **FAIL**: EHTTPS_HOSTNAME_MISMATCH | SAN/CN matching |
| 9449 | Revoked cert | **FAIL**: EHTTPS_CERT_REVOKED | OCSP/CRL checking |
| 9450 | HTTP/2 only | Success with HTTP/2 | ALPN negotiation, HTTP/2 multiplexing |
| 9451 | Slow responses | Configurable delay | Timeout handling |
| 9452 | Large responses | Configurable size | Memory handling |
| 9453 | OCSP Stapling | Success with stapled OCSP | OCSP stapling, revocation cache TTL |

### Proxy Endpoints

| Port | Description | Credentials |
|------|-------------|-------------|
| 9128 | HTTP proxy (no auth) | None |
| 9129 | HTTP proxy (basic auth) | testuser / testpassword |

### Support Services

| Port | Description |
|------|-------------|
| 9888 | OCSP Responder |
| 9889 | CRL Distribution Point |

---

## Using with SecureWebFetch

### 1. Copy CA Bundle

The CA bundle is required for SecureWebFetch to trust the test certificates:

```bash
# From test-server directory
cat pki/ca-bundle.crt
```

Copy this file to your config and configure:
- **CA Mode**: Custom Bundle
- **Custom CA Bundle Path**: `/path/to/ca-bundle.crt`

### 2. Client Certificate for mTLS

For testing the mTLS endpoint (port 9445):

**Certificate**: `pki/client-certs/valid-client.crt`
**Private Key**: `pki/client-certs/valid-client.key`

Or use the PKCS#12 bundle:
**File**: `pki/client-certs/valid-client.p12`
**Password**: `testpassword`

### 3. SPKI Hashes for Pinning

For testing certificate pinning:

```bash
cat pki/pinning-hashes.txt
```

Use these hashes in the HTTPS node's pinning configuration.

### 4. Enabling Pro Features for Testing

Pro features (mTLS, FIPS, SIEM, OCSP Stapling, etc.) require a valid license.

Add your license key to `~/.claude/https-config.json`:

```json
{
  "license": {
    "key": "HTTPS-<your-license-key>"
  }
}
```

**Pro Feature Tests:**
- mTLS (requires Pro)
- FIPS Mode (requires Pro)
- Revocation checking with OCSP/CRL (requires Pro)
- Certificate pinning (requires Pro)

---

## Backend Echo Server

The backend server echoes back request details. You can control its behavior with headers:

| Header | Description | Example |
|--------|-------------|---------|
| `X-Delay-Ms` | Delay response by N milliseconds | `X-Delay-Ms: 5000` |
| `X-Response-Size` | Add N bytes of padding to response | `X-Response-Size: 1048576` |
| `X-Status-Code` | Return custom status code | `X-Status-Code: 500` |
| `X-Error-Type` | Simulate errors | `X-Error-Type: timeout` |

### Error Types

- `connection-reset` - Immediately reset the connection
- `timeout` / `hang` - Never respond (test timeout handling)
- `slow-headers` - Delay 60s before sending headers

### Special Endpoints (Port 9451 - Slow)

- `/hang` - Never responds (timeout testing)
- `/delay/5000` - Delays 5000ms before responding

### Special Endpoints (Port 9452 - Large)

- `/1kb` - Returns ~1KB response
- `/100kb` - Returns ~100KB response
- `/1mb` - Returns ~1MB response
- `/10mb` - Returns ~10MB response
- `/size/12345` - Returns exactly 12345 bytes

---

## Make Commands

```bash
make help       # Show all commands
make start      # Generate certs and start services
make stop       # Stop all services
make restart    # Restart services
make logs       # View logs (follow mode)
make certs      # Regenerate certificates
make clean      # Remove everything
make test       # Run connectivity tests
make status     # Show service status
make build      # Rebuild Docker images
make shell      # Shell into nginx container
make cert-info  # Display certificate details
make pinning-hashes  # Show SPKI hashes for pinning
make package    # Create deployment tarball
```

---

## Troubleshooting

### Certificates Not Generated

```bash
make certs
```

### Port Already in Use

```bash
# Check what's using the port
lsof -i :9443

# Or change ports in docker-compose.yml
```

### nginx Won't Start

```bash
# Check nginx config
docker-compose exec nginx nginx -t

# View nginx logs
docker-compose logs nginx
```

### mTLS Failing

1. Ensure you're using the correct client certificate
2. Verify the CA bundle includes the intermediate CA
3. Check that the client cert was signed by our CA

```bash
# Verify client cert
openssl verify -CAfile pki/ca-bundle.crt pki/client-certs/valid-client.crt
```

### OCSP Not Working

The OCSP responder requires the CA index to be populated:

```bash
# Regenerate certificates
make clean
make certs
make start
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Docker Network                           │
│                                                                 │
│  ┌─────────────┐    ┌──────────────────────────────────────┐   │
│  │   nginx     │    │           Backend Server             │   │
│  │   :9080-    │───▶│           :3000                      │   │
│  │   :9452     │    │                                      │   │
│  │             │    │   Echo server that returns request   │   │
│  │   Multiple  │    │   details in JSON format             │   │
│  │   TLS       │    │                                      │   │
│  │   configs   │    └──────────────────────────────────────┘   │
│  └─────────────┘                                               │
│         │                                                       │
│         │            ┌──────────────────────────────────────┐   │
│         └───────────▶│           OCSP Responder            │   │
│                      │           :9888                      │   │
│                      └──────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────┐    ┌──────────────────────────────────────┐   │
│  │   Squid     │    │           CRL Server                 │   │
│  │   Proxy     │    │           :9889                      │   │
│  │   :9128-9   │    │                                      │   │
│  └─────────────┘    └──────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Files

```
test-server/
├── docker-compose.yml      # Service definitions
├── Makefile                # Easy commands
├── README.md               # This file
│
├── nginx/
│   ├── nginx.conf          # Main nginx config
│   ├── crl.conf            # CRL server config
│   └── sites/              # Per-port configurations
│       ├── default.conf    # Port 9080 (HTTP)
│       ├── tls13-only.conf # Port 9443
│       ├── tls12-only.conf # Port 9444
│       ├── mtls.conf       # Port 9445
│       ├── expired.conf    # Port 9446
│       ├── selfsigned.conf # Port 9447
│       ├── wronghost.conf  # Port 9448
│       ├── revoked.conf    # Port 9449
│       ├── http2only.conf  # Port 9450
│       ├── slow.conf       # Port 9451
│       ├── large.conf      # Port 9452
│       └── ocsp-stapling.conf # Port 9453
│
├── pki/
│   ├── generate-certs.sh   # Certificate generator
│   ├── ca-bundle.crt       # CA bundle for clients
│   ├── pinning-hashes.txt  # SPKI hashes
│   ├── root-ca/            # Root CA cert/key
│   ├── intermediate-ca/    # Intermediate CA
│   ├── server-certs/       # Server certificates
│   │   ├── valid/
│   │   ├── expired/
│   │   ├── revoked/
│   │   ├── selfsigned/
│   │   └── wronghost/
│   ├── client-certs/       # Client certificates
│   └── crl/                # Certificate Revocation List
│
├── backend/
│   ├── Dockerfile
│   ├── package.json
│   └── server.js           # Echo server
│
├── ocsp/
│   ├── Dockerfile
│   └── start-ocsp.sh       # OCSP responder
│
└── proxy/
    ├── Dockerfile
    └── squid.conf          # Proxy configuration
```

---

## License

MIT
