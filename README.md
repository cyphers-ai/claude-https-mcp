# Claude HTTPS MCP Tool

An MCP (Model Context Protocol) server that provides a secure HTTPS fetch tool for Claude Code, with custom TLS configuration loaded from a JSON config file.

## Features

### Free Features
- **TLS Version Control**: Configure minimum and maximum TLS versions (TLS 1.2, TLS 1.3)
- **Cipher Suite Profiles**: Modern, Intermediate, Compatible, or Custom cipher suites
- **CA Certificate Modes**: Bundled Mozilla CA bundle, OS trust store, or custom CA paths
- **Proxy Support**: HTTP proxy with basic authentication
- **Configurable Timeouts**: Request timeout configuration

### Pro Features (require license)
- **mTLS**: Mutual TLS with client certificates (PEM or PKCS#12)
- **Certificate Pinning**: Pin by leaf, intermediate, root certificate, or SPKI hash
- **FIPS Mode**: FIPS 140-3 compliant cipher suites
- **Revocation Checking**: OCSP and CRL checking with soft/hard fail modes

## Installation

### Quick Install (Recommended)

```bash
npm install -g claude-https-mcp
claude mcp add --scope user --transport stdio claude-https-mcp -- claude-https-mcp
```

Verify the installation:
```bash
claude mcp list
```

### npx (Zero-Install)

```bash
claude mcp add --scope user --transport stdio claude-https-mcp -- npx claude-https-mcp
```

### From Source

```bash
git clone https://github.com/cyphers-ai/claude-https-mcp.git
cd claude-https-mcp
npm install
npm run build
npm link
claude mcp add --scope user --transport stdio claude-https-mcp -- claude-https-mcp
```

## Configuration

Create a configuration file at `~/.claude/https-config.json`:

```json
{
  "tls": {
    "minVersion": "TLSv1.2",
    "maxVersion": "TLSv1.3",
    "cipherProfile": "intermediate",
    "customCiphers": null,
    "rejectUnauthorized": true
  },
  "ca": {
    "mode": "bundled",
    "customBundlePaths": [],
    "additionalCaPaths": []
  },
  "clientCert": {
    "enabled": false,
    "certPath": null,
    "keyPath": null,
    "passphrase": null,
    "p12Path": null,
    "p12Passphrase": null
  },
  "pinning": {
    "enabled": false,
    "mode": "leaf",
    "pins": []
  },
  "revocation": {
    "enabled": false,
    "policy": "ocspWithCrlFallback",
    "failMode": "soft",
    "cacheTtlSeconds": 300
  },
  "proxy": {
    "enabled": false,
    "url": null,
    "auth": {
      "type": "none",
      "username": null,
      "password": null
    },
    "bypassList": []
  },
  "defaults": {
    "timeoutMs": 30000,
    "followRedirects": true,
    "maxRedirects": 10
  },
  "license": {
    "key": null
  }
}
```

See `example-config.json` for a fully documented example.

### Configuration Options

#### TLS Settings

| Option | Values | Description |
|--------|--------|-------------|
| `minVersion` | `TLSv1.2`, `TLSv1.3` | Minimum TLS version |
| `maxVersion` | `TLSv1.2`, `TLSv1.3` | Maximum TLS version |
| `cipherProfile` | `modern`, `intermediate`, `compatible`, `fips`, `custom` | Cipher suite profile |
| `customCiphers` | OpenSSL cipher string | Custom cipher string (when profile is `custom`) |
| `rejectUnauthorized` | `true`, `false` | Validate server certificates |

#### CA Modes

| Mode | Description |
|------|-------------|
| `bundled` | Use Mozilla CA bundle (default) |
| `osPlusBundled` | Use OS trust store + Mozilla bundle |
| `osOnly` | Use OS trust store only |
| `custom` | Use custom CA files only |

#### Cipher Profiles

| Profile | Description |
|---------|-------------|
| `modern` | TLS 1.3 only, strongest security |
| `intermediate` | TLS 1.2+, balanced security/compatibility (recommended) |
| `compatible` | Wider support, still no legacy ciphers |
| `fips` | FIPS 140-3 approved ciphers only (Pro) |
| `custom` | User-defined cipher string |

## Usage

Once configured, Claude Code will have access to the `SecureWebFetch` tool:

```
Use SecureWebFetch to get https://api.example.com/data
```

### Tool Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | Yes | The HTTPS URL to fetch |
| `method` | string | No | HTTP method (GET, POST, etc.) |
| `headers` | object | No | Request headers |
| `body` | string | No | Request body |
| `timeout` | number | No | Request timeout in ms |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CLAUDE_HTTPS_CONFIG` | Override config file path |

## License

This project uses the same licensing model as the n8n-https node:
- Free features available without a license
- Pro features require a license from https://cyphers.ai

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Watch mode
npm run dev
```
