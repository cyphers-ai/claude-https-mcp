---
name: secure-https
description: Secure HTTPS fetch with custom TLS configuration for Claude Code. Use when making HTTPS requests that require mutual TLS (mTLS), certificate pinning, FIPS compliance, custom CA bundles, or corporate proxy support. Triggers on "fetch securely", "mTLS request", "pin certificate", "FIPS mode", or when SecureWebFetch tool is available.
license: MIT
metadata:
  author: cyphers-ai
  version: "1.0.0"
---

# Secure HTTPS Fetch

Make HTTPS requests with enterprise-grade TLS configuration using the `SecureWebFetch` MCP tool. Supports mutual TLS, certificate pinning, OCSP/CRL revocation checking, FIPS 140-3 compliance, custom CA bundles, and corporate proxy tunneling.

## Prerequisites

The `SecureWebFetch` MCP tool must be registered with Claude Code. If it is not available, run the setup script:

```bash
bash ~/.claude/skills/secure-https/scripts/setup.sh
```

## When to Use SecureWebFetch

Use `SecureWebFetch` instead of regular web fetch when:
- The target API requires **client certificate authentication** (mTLS)
- You need **certificate pinning** to prevent MITM attacks
- The environment requires **FIPS 140-3** compliant cryptography
- You need to trust **internal/private CA certificates** (corporate PKI)
- Requests must go through a **corporate HTTP proxy**
- You want explicit control over **TLS version and cipher suites**

For simple public HTTPS requests where none of the above apply, the built-in fetch is sufficient.

## Basic Usage

```
Use SecureWebFetch to fetch https://api.example.com/data
```

### GET Request

```json
{
  "url": "https://api.example.com/data"
}
```

### POST with Headers and Body

```json
{
  "url": "https://api.example.com/submit",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json",
    "Authorization": "Bearer <token>"
  },
  "body": "{\"key\": \"value\"}"
}
```

### Custom Timeout

```json
{
  "url": "https://slow-api.example.com/report",
  "timeout": 60000
}
```

## Configuration

All TLS behavior is controlled by `~/.claude/https-config.json`. The user configures this file once; you do not need to pass TLS settings per-request.

### Key Configuration Scenarios

**Trust internal CA certificates** (corporate environments):
```json
{
  "ca": {
    "mode": "osPlusBundled",
    "additionalCaPaths": ["/path/to/internal-ca.pem"]
  }
}
```

**Mutual TLS with client certificate**:
```json
{
  "clientCert": {
    "enabled": true,
    "certPath": "/path/to/client.crt",
    "keyPath": "/path/to/client.key"
  }
}
```

**Corporate proxy**:
```json
{
  "proxy": {
    "enabled": true,
    "url": "http://proxy.corp.example.com:8080",
    "auth": { "type": "basic", "username": "user", "password": "pass" }
  }
}
```

## Error Handling

When `SecureWebFetch` returns an error, the error code tells you exactly what went wrong:

| Error Code | Meaning | What to Tell the User |
|------------|---------|----------------------|
| `EHTTPS_TLS_HANDSHAKE` | TLS negotiation failed | Server may not support the configured TLS version or ciphers. Check `tls.minVersion` and `tls.cipherProfile` in config. |
| `EHTTPS_CERT_VERIFY` | Server certificate validation failed | The server's certificate is not trusted. If using an internal CA, set `ca.mode` to `"osPlusBundled"` or add the CA to `ca.additionalCaPaths`. |
| `EHTTPS_CERT_EXPIRED` | Server certificate has expired | The server's TLS certificate has expired. This is a server-side issue. |
| `EHTTPS_HOSTNAME_MISMATCH` | Certificate doesn't match hostname | The server certificate was issued for a different domain. |
| `EHTTPS_PIN_MISMATCH` | Certificate pinning failed | The server's certificate doesn't match any configured pins. The certificate may have been rotated — update `pinning.pins` in config. |
| `EHTTPS_CERT_REVOKED` | Certificate has been revoked | The server's certificate was revoked by its CA. Do not proceed. |
| `EHTTPS_TIMEOUT` | Request timed out | Increase `timeout` parameter or check network connectivity. |
| `EHTTPS_CONNECTION_REFUSED` | Connection refused | The server is not accepting connections on that port. |
| `EHTTPS_DNS_RESOLVE` | DNS resolution failed | The hostname could not be resolved. Check the URL. |
| `EHTTPS_PROXY_AUTH` | Proxy authentication failed | Proxy credentials in config are incorrect. |
| `EHTTPS_PROXY_CONNECT` | Proxy CONNECT tunnel failed | The proxy refused the CONNECT request. Check proxy URL and permissions. |
| `EHTTPS_FIPS_NOT_AVAILABLE` | FIPS mode not active | The `fips` cipher profile requires a FIPS-enabled Node.js build. |
| `EHTTPS_LICENSE_REQUIRED` | Pro license required | The requested feature (mTLS, pinning, FIPS) requires a Pro license from cyphers.ai. |
| `EHTTPS_BODY_TOO_LARGE` | Request body exceeds size limit | The request body exceeds `defaults.maxBodySizeBytes` (default 10 MB). |
| `EHTTPS_CONFIG_INVALID` | Configuration file is invalid | There is a syntax or validation error in `~/.claude/https-config.json`. |

## Present Results to User

When presenting SecureWebFetch results:

1. Show the **HTTP status code** and whether the request succeeded
2. For JSON responses, format the body as a code block
3. If the request failed with an error code from the table above, explain what went wrong and suggest the fix
4. Never expose raw headers unless the user asks for them

## Troubleshooting

### "SecureWebFetch tool is not available"
The MCP server is not registered. Run:
```bash
bash ~/.claude/skills/secure-https/scripts/setup.sh
```

### "EHTTPS_CERT_VERIFY" on internal APIs
The server uses a private CA. Update `~/.claude/https-config.json`:
```json
{ "ca": { "mode": "osPlusBundled" } }
```
Or add the CA certificate path to `ca.additionalCaPaths`.

### "EHTTPS_TLS_HANDSHAKE" failures
The server may require an older TLS configuration. Try changing `tls.cipherProfile` from `"modern"` to `"intermediate"` in the config file.

### Proxy issues in corporate environments
Ensure `proxy.enabled` is `true` and `proxy.url` points to the correct proxy. Add internal domains to `proxy.bypassList` to skip the proxy for local services.
