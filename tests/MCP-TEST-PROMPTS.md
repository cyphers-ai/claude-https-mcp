# SecureWebFetch MCP Tool Test Prompts

After restarting Claude Code, use these prompts to test the SecureWebFetch tool against the local test server.

## Prerequisites

1. **Start the test server:**
   ```bash
   cd /Users/rogerioricha/code/claude-https
   npm run test:server:start
   ```

2. **Restart Claude Code** to load the MCP server

3. **Verify test server is running:**
   ```bash
   npm run test:server:test
   ```

---

## Test Prompts

### 1. Basic TLS 1.3 (should succeed)
```
Use SecureWebFetch to fetch https://localhost:9443/health
```

### 2. TLS 1.2 Endpoint (should succeed)
```
Use SecureWebFetch to fetch https://localhost:9444/health
```

### 3. HTTP/2 Endpoint (should succeed)
```
Use SecureWebFetch to fetch https://localhost:9450/health
```

### 4. Expired Certificate (should fail with cert error)
```
Use SecureWebFetch to fetch https://localhost:9446/health
```

### 5. Self-Signed Certificate (should fail with trust error)
```
Use SecureWebFetch to fetch https://localhost:9447/health
```

### 6. Wrong Hostname (should fail with hostname mismatch)
```
Use SecureWebFetch to fetch https://localhost:9448/health
```

### 7. POST Request with JSON Body
```
Use SecureWebFetch to POST {"test": "hello world"} to https://localhost:9443/ with header Content-Type: application/json
```

### 8. Timeout Test (should timeout)
```
Use SecureWebFetch to fetch https://localhost:9451/delay/10000 with a 5000ms timeout
```

### 9. Large Response (100KB)
```
Use SecureWebFetch to fetch https://localhost:9452/100kb
```

### 10. Custom Headers
```
Use SecureWebFetch to GET https://localhost:9443/ with headers X-Custom-Header: test-value and Accept: application/json
```

---

## Pro Feature Tests (require license)

### 11. mTLS Endpoint (requires Pro license)
```
Use SecureWebFetch to fetch https://localhost:9445/health
```
*Note: Will fail without mTLS client cert configured in ~/.claude/https-config.json*

### 12. Revoked Certificate (requires Pro license for OCSP/CRL)
```
Use SecureWebFetch to fetch https://localhost:9449/health
```

---

## Expected Results Summary

| Test | Port | Expected |
|------|------|----------|
| TLS 1.3 | 9443 | Success |
| TLS 1.2 | 9444 | Success |
| HTTP/2 | 9450 | Success |
| Expired | 9446 | Error: certificate expired |
| Self-signed | 9447 | Error: unable to verify |
| Wrong host | 9448 | Error: hostname mismatch |
| Timeout | 9451 | Error: timeout |
| Large | 9452 | Success (truncated) |
| mTLS | 9445 | Error (unless Pro + config) |
| Revoked | 9449 | Error (if Pro enabled) |

---

## Stopping the Test Server

```bash
npm run test:server:stop
```
