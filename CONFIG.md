# SecureWebFetch Configuration Guide

This guide explains how to configure the `~/.claude/https-config.json` file for the SecureWebFetch MCP tool.

## Quick Start

1. Copy the example config to your Claude config directory:
   ```bash
   cp example-config.json ~/.claude/https-config.json
   ```

2. Edit the file to match your needs (see sections below)

3. Restart Claude Code for changes to take effect

---

## Configuration File Location

| Platform | Path |
|----------|------|
| macOS/Linux | `~/.claude/https-config.json` |
| Windows | `%USERPROFILE%\.claude\https-config.json` |

You can override this with the `CLAUDE_HTTPS_CONFIG` environment variable.

---

## TLS Settings

```json
"tls": {
  "minVersion": "TLSv1.2",
  "maxVersion": "TLSv1.3",
  "cipherProfile": "intermediate",
  "rejectUnauthorized": true
}
```

### minVersion / maxVersion

| Value | Description | Recommendation |
|-------|-------------|----------------|
| `TLSv1.2` | TLS 1.2 | Minimum for most use cases |
| `TLSv1.3` | TLS 1.3 | Most secure, use if servers support it |

**Recommended:** `minVersion: "TLSv1.2"`, `maxVersion: "TLSv1.3"`

### cipherProfile

| Profile | Description | Use Case |
|---------|-------------|----------|
| `modern` | TLS 1.3 ciphers only | Maximum security, TLS 1.3 servers only |
| `intermediate` | TLS 1.2 + 1.3 ciphers | **Recommended** - balances security and compatibility |
| `compatible` | Includes older ciphers | Legacy server support (less secure) |
| `fips` | FIPS 140-3 compatible ciphers | Requires FIPS-enabled OpenSSL (Pro) |
| `custom` | User-defined | Advanced users only |

**Recommended:** `intermediate`

### rejectUnauthorized

| Value | Description |
|-------|-------------|
| `true` | **Recommended** - Validates server certificates |
| `false` | Disables certificate validation (INSECURE) |

**Warning:** Never set `rejectUnauthorized: false` in production. This disables all certificate checks and makes connections vulnerable to man-in-the-middle attacks.

---

## CA Certificate Settings

```json
"ca": {
  "mode": "bundled",
  "customBundlePaths": [],
  "additionalCaPaths": []
}
```

### mode

| Mode | Description | Use Case |
|------|-------------|----------|
| `bundled` | Mozilla CA bundle (included) | **Recommended** - works with public websites |
| `osPlusBundled` | OS trust store + Mozilla bundle | Use if you need OS-installed certs |
| `osOnly` | OS trust store only | Corporate environments with managed certs |
| `custom` | Only custom CA files | Air-gapped or private PKI environments |

### customBundlePaths

Array of paths to CA bundle files. Only used when `mode: "custom"`.

```json
"customBundlePaths": [
  "/path/to/corporate-ca-bundle.pem"
]
```

### additionalCaPaths

Array of additional CA certificates to trust (added to any mode).

```json
"additionalCaPaths": [
  "/path/to/internal-ca.crt",
  "/path/to/partner-ca.crt"
]
```

**Use cases:**
- Internal corporate PKI
- Partner/vendor certificates
- Development/testing with self-signed certs

---

## Client Certificate (mTLS) - Pro Feature

Mutual TLS authentication with client certificates.

```json
"clientCert": {
  "enabled": true,
  "certPath": "/path/to/client.crt",
  "keyPath": "/path/to/client.key",
  "passphrase": null
}
```

Or using PKCS#12 format:

```json
"clientCert": {
  "enabled": true,
  "p12Path": "/path/to/client.p12",
  "p12Passphrase": "your-password"
}
```

| Field | Description |
|-------|-------------|
| `enabled` | Enable/disable mTLS |
| `certPath` | Path to PEM certificate file |
| `keyPath` | Path to PEM private key file |
| `passphrase` | Private key passphrase (if encrypted) |
| `p12Path` | Path to PKCS#12 bundle (alternative to PEM) |
| `p12Passphrase` | PKCS#12 password |

**Security Notes:**
- Store private keys with restricted permissions (`chmod 600`)
- Consider using PKCS#12 with a strong passphrase
- Never commit certificates/keys to version control

---

## Certificate Pinning - Pro Feature

Pin specific certificates to prevent MITM attacks.

```json
"pinning": {
  "enabled": true,
  "mode": "spki",
  "pins": [
    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
  ]
}
```

### mode

| Mode | Description |
|------|-------------|
| `leaf` | Pin the server's certificate |
| `intermediate` | Pin the intermediate CA |
| `root` | Pin the root CA |
| `spki` | Pin the Subject Public Key Info hash |

**Recommended:** `spki` - survives certificate renewals

### Getting SPKI Hashes

```bash
# From a live server
openssl s_client -connect example.com:443 2>/dev/null | \
  openssl x509 -pubkey -noout | \
  openssl pkey -pubin -outform DER | \
  openssl dgst -sha256 -binary | \
  base64

# From a certificate file
openssl x509 -in cert.pem -pubkey -noout | \
  openssl pkey -pubin -outform DER | \
  openssl dgst -sha256 -binary | \
  base64
```

---

## Certificate Revocation - Pro Feature

Check if certificates have been revoked.

```json
"revocation": {
  "enabled": true,
  "policy": "ocspWithCrlFallback",
  "failMode": "soft",
  "enableStapling": true,
  "cacheTtlSeconds": 300
}
```

### policy

| Policy | Description |
|--------|-------------|
| `ocspWithCrlFallback` | Try OCSP first, fall back to CRL |
| `ocspOnly` | OCSP only |
| `crlOnly` | CRL only |
| `bothRequired` | Both OCSP and CRL must pass |

### failMode

| Mode | Description |
|------|-------------|
| `soft` | Allow connection if revocation check fails |
| `hard` | Block connection if revocation check fails |

**Recommendation:** Use `soft` for availability, `hard` for high-security environments.

### enableStapling

When `true`, accepts OCSP stapled responses from the server (more efficient).

---

## Proxy Settings

```json
"proxy": {
  "enabled": true,
  "url": "http://proxy.company.com:8080",
  "auth": {
    "type": "basic",
    "username": "user",
    "password": "pass"
  },
  "bypassList": [
    "localhost",
    "*.internal.company.com"
  ]
}
```

### auth.type

| Type | Description |
|------|-------------|
| `none` | No authentication |
| `basic` | HTTP Basic auth |
| `digest` | HTTP Digest auth |
| `ntlm` | NTLM authentication (Windows) |

### bypassList

Hostnames/patterns that should bypass the proxy.

---

## Default Request Settings

```json
"defaults": {
  "timeoutMs": 30000,
  "followRedirects": true,
  "maxRedirects": 10,
  "maxBodySizeBytes": 10485760
}
```

| Field | Description | Default |
|-------|-------------|---------|
| `timeoutMs` | Request timeout in milliseconds | 30000 |
| `followRedirects` | Automatically follow redirects | true |
| `maxRedirects` | Maximum redirect hops | 10 |
| `maxBodySizeBytes` | Maximum request body size in bytes | 10485760 (10 MB) |

---

## License

```json
"license": {
  "key": "HTTPS-xxxxx.xxxxx"
}
```

Pro features require a valid license key. Acquire at [cyphers.ai](https://cyphers.ai).

**Pro Features:**
- mTLS (Client Certificates)
- Certificate Pinning
- OCSP/CRL Revocation Checking
- FIPS 140-3 Compatible Cipher Suites (requires FIPS-enabled OpenSSL)
- SIEM Log Export

---

## Security Best Practices

1. **Always validate certificates**
   ```json
   "rejectUnauthorized": true
   ```

2. **Use TLS 1.2 minimum**
   ```json
   "minVersion": "TLSv1.2"
   ```

3. **Use intermediate cipher profile** for compatibility
   ```json
   "cipherProfile": "intermediate"
   ```

4. **Protect private keys**
   - Use file permissions: `chmod 600 key.pem`
   - Use encrypted PKCS#12 when possible
   - Never commit to version control

5. **Enable revocation checking** for high-security environments
   ```json
   "revocation": { "enabled": true, "failMode": "hard" }
   ```

6. **Use certificate pinning** for critical endpoints
   ```json
   "pinning": { "enabled": true, "mode": "spki", "pins": [...] }
   ```

---

## Troubleshooting

### Certificate Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `EHTTPS_CERT_VERIFY` | Certificate validation failed | Check CA config, add CA to `additionalCaPaths` |
| `EHTTPS_CERT_EXPIRED` | Certificate has expired | Contact server admin |
| `EHTTPS_HOSTNAME_MISMATCH` | Cert doesn't match hostname | Verify you're connecting to correct host |
| `EHTTPS_CERT_REVOKED` | Certificate was revoked | Contact server admin |

### Connection Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `EHTTPS_TIMEOUT` | Request timed out | Increase `timeoutMs` or check network |
| `EHTTPS_TLS_VERSION` | TLS version mismatch | Adjust `minVersion`/`maxVersion` |
| `EHTTPS_CIPHER` | No common ciphers | Try `cipherProfile: "compatible"` |

### Validate Your Config

Use the config validator at [cyphers.ai/validate](https://cyphers.ai/validate) to check your configuration.

---

## Example Configurations

### Minimal (Public Websites)

```json
{
  "tls": {
    "minVersion": "TLSv1.2",
    "maxVersion": "TLSv1.3",
    "cipherProfile": "intermediate",
    "rejectUnauthorized": true
  },
  "ca": {
    "mode": "bundled"
  }
}
```

### Corporate Environment

```json
{
  "tls": {
    "minVersion": "TLSv1.2",
    "maxVersion": "TLSv1.3",
    "cipherProfile": "intermediate",
    "rejectUnauthorized": true
  },
  "ca": {
    "mode": "osPlusBundled",
    "additionalCaPaths": [
      "/etc/ssl/corporate-ca.crt"
    ]
  },
  "proxy": {
    "enabled": true,
    "url": "http://proxy.corp.com:8080",
    "bypassList": ["*.corp.com", "localhost"]
  }
}
```

### High Security

```json
{
  "tls": {
    "minVersion": "TLSv1.3",
    "maxVersion": "TLSv1.3",
    "cipherProfile": "modern",
    "rejectUnauthorized": true
  },
  "ca": {
    "mode": "bundled"
  },
  "pinning": {
    "enabled": true,
    "mode": "spki",
    "pins": ["sha256/..."]
  },
  "revocation": {
    "enabled": true,
    "policy": "ocspWithCrlFallback",
    "failMode": "hard"
  },
  "license": {
    "key": "HTTPS-..."
  }
}
```
