import { describe, it, expect } from 'vitest';
import {
  makeRequest,
  buildProxyAuthHeader,
  shouldBypassProxy,
  parseRawHttpResponse,
  mapError,
} from '../http/client.js';
import { DEFAULT_CONFIG } from '../config/loader.js';
import type { HttpsConfig } from '../config/types.js';

/**
 * Helper to create a config with deep overrides from DEFAULT_CONFIG.
 * Accepts dot-separated paths for nested properties.
 */
function makeConfig(overrides: Record<string, unknown> = {}): HttpsConfig {
  const config = JSON.parse(JSON.stringify(DEFAULT_CONFIG)) as HttpsConfig;
  for (const [key, value] of Object.entries(overrides)) {
    const parts = key.split('.');
    let target: Record<string, unknown> = config as unknown as Record<string, unknown>;
    for (let i = 0; i < parts.length - 1; i++) {
      target = target[parts[i]] as Record<string, unknown>;
    }
    target[parts[parts.length - 1]] = value;
  }
  return config;
}

/**
 * Helper to create a Node.js-style error with an errno code property.
 */
function makeNodeError(message: string, code?: string): NodeJS.ErrnoException {
  const err = new Error(message) as NodeJS.ErrnoException;
  if (code) {
    err.code = code;
  }
  return err;
}

// ---------------------------------------------------------------------------
// shouldBypassProxy
// ---------------------------------------------------------------------------
describe('shouldBypassProxy', () => {
  it('returns false for an empty bypass list', () => {
    expect(shouldBypassProxy('example.com', [])).toBe(false);
  });

  it('returns true for an exact hostname match', () => {
    expect(shouldBypassProxy('example.com', ['example.com'])).toBe(true);
  });

  it('returns true when hostname is a subdomain of a pattern', () => {
    expect(shouldBypassProxy('sub.example.com', ['example.com'])).toBe(true);
  });

  it('returns true for a leading-dot pattern matching a subdomain', () => {
    expect(shouldBypassProxy('sub.example.com', ['.example.com'])).toBe(true);
  });

  it('returns true for a leading-dot pattern matching the bare domain', () => {
    expect(shouldBypassProxy('example.com', ['.example.com'])).toBe(true);
  });

  it('returns false when hostname merely ends with but is not a subdomain of the pattern', () => {
    expect(shouldBypassProxy('notexample.com', ['example.com'])).toBe(false);
  });

  it('returns true when hostname matches any entry in a multi-pattern list', () => {
    expect(shouldBypassProxy('other.com', ['example.com', 'other.com'])).toBe(true);
  });

  it('returns false when bypassList is null (defensive)', () => {
    expect(shouldBypassProxy('test.com', null as any)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// buildProxyAuthHeader
// ---------------------------------------------------------------------------
describe('buildProxyAuthHeader', () => {
  it('returns null when auth type is none', () => {
    const config = makeConfig({
      'proxy.auth.type': 'none',
      'proxy.auth.username': 'user',
      'proxy.auth.password': 'pass',
    });
    expect(buildProxyAuthHeader(config)).toBeNull();
  });

  it('returns a Basic auth header with base64-encoded credentials', () => {
    const config = makeConfig({
      'proxy.auth.type': 'basic',
      'proxy.auth.username': 'alice',
      'proxy.auth.password': 's3cret',
    });
    const header = buildProxyAuthHeader(config);
    const expected = 'Basic ' + Buffer.from('alice:s3cret').toString('base64');
    expect(header).toBe(expected);
  });

  it('returns a Basic auth header with empty password when password is null', () => {
    const config = makeConfig({
      'proxy.auth.type': 'basic',
      'proxy.auth.username': 'bob',
      'proxy.auth.password': null,
    });
    const header = buildProxyAuthHeader(config);
    const expected = 'Basic ' + Buffer.from('bob:').toString('base64');
    expect(header).toBe(expected);
  });

  it('returns null when auth type is basic but username is missing', () => {
    const config = makeConfig({
      'proxy.auth.type': 'basic',
      'proxy.auth.username': null,
      'proxy.auth.password': 'pass',
    });
    expect(buildProxyAuthHeader(config)).toBeNull();
  });

  it('throws for digest auth type', () => {
    const config = makeConfig({
      'proxy.auth.type': 'digest',
      'proxy.auth.username': 'user',
      'proxy.auth.password': 'pass',
    });
    expect(() => buildProxyAuthHeader(config)).toThrow('not yet supported');
  });

  it('throws for ntlm auth type', () => {
    const config = makeConfig({
      'proxy.auth.type': 'ntlm',
      'proxy.auth.username': 'user',
      'proxy.auth.password': 'pass',
    });
    expect(() => buildProxyAuthHeader(config)).toThrow('not yet supported');
  });
});

// ---------------------------------------------------------------------------
// parseRawHttpResponse
// ---------------------------------------------------------------------------
describe('parseRawHttpResponse', () => {
  it('parses a standard 200 OK response with body', () => {
    const raw = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nbody';
    const result = parseRawHttpResponse(raw);

    expect(result.statusCode).toBe(200);
    expect(result.statusMessage).toBe('OK');
    expect(result.headers['content-type']).toBe('text/html');
    expect(result.body).toBe('body');
  });

  it('parses a 404 Not Found response with an empty body', () => {
    const raw = 'HTTP/1.1 404 Not Found\r\n\r\n';
    const result = parseRawHttpResponse(raw);

    expect(result.statusCode).toBe(404);
    expect(result.statusMessage).toBe('Not Found');
    expect(result.body).toBe('');
  });

  it('returns statusCode 0 and empty body for an empty string', () => {
    const result = parseRawHttpResponse('');

    expect(result.statusCode).toBe(0);
    expect(result.statusMessage).toBe('');
    expect(result.body).toBe('');
  });

  it('returns statusCode 0 for a malformed response', () => {
    const result = parseRawHttpResponse('malformed');

    expect(result.statusCode).toBe(0);
    expect(result.statusMessage).toBe('');
  });

  it('lowercases header names', () => {
    const raw = 'HTTP/1.1 200 OK\r\nX-Custom-Header: value\r\nContent-Type: application/json\r\n\r\n';
    const result = parseRawHttpResponse(raw);

    expect(result.headers['x-custom-header']).toBe('value');
    expect(result.headers['content-type']).toBe('application/json');
    // Ensure the original casing is not present
    expect(result.headers['X-Custom-Header']).toBeUndefined();
  });

  it('parses multiple headers correctly', () => {
    const raw =
      'HTTP/1.1 200 OK\r\n' +
      'Content-Type: text/plain\r\n' +
      'X-Request-Id: abc-123\r\n' +
      'Cache-Control: no-cache\r\n' +
      '\r\n' +
      'hello';
    const result = parseRawHttpResponse(raw);

    expect(result.headers['content-type']).toBe('text/plain');
    expect(result.headers['x-request-id']).toBe('abc-123');
    expect(result.headers['cache-control']).toBe('no-cache');
    expect(result.body).toBe('hello');
  });

  it('preserves special characters in the body', () => {
    const raw = 'HTTP/1.1 200 OK\r\n\r\n<html>&amp; "quotes" \'single\' \ttab\nnewline</html>';
    const result = parseRawHttpResponse(raw);

    expect(result.body).toBe('<html>&amp; "quotes" \'single\' \ttab\nnewline</html>');
  });

  it('returns empty body when there is no header/body separator', () => {
    const raw = 'HTTP/1.1 200 OK\r\nContent-Type: text/html';
    const result = parseRawHttpResponse(raw);

    // Without \r\n\r\n, the whole string is treated as the header part
    expect(result.body).toBe('');
    expect(result.statusCode).toBe(200);
    expect(result.headers['content-type']).toBe('text/html');
  });
});

// ---------------------------------------------------------------------------
// mapError
// ---------------------------------------------------------------------------
describe('mapError', () => {
  it('maps ECONNREFUSED to EHTTPS_CONNECTION_REFUSED', () => {
    const err = makeNodeError('connect ECONNREFUSED 127.0.0.1:443', 'ECONNREFUSED');
    const mapped = mapError(err);

    expect(mapped.message).toContain('EHTTPS_CONNECTION_REFUSED');
    expect(mapped.message).toContain('Connection refused');
  });

  it('maps ENOTFOUND to EHTTPS_DNS_RESOLVE', () => {
    const err = makeNodeError('getaddrinfo ENOTFOUND example.invalid', 'ENOTFOUND');
    const mapped = mapError(err);

    expect(mapped.message).toContain('EHTTPS_DNS_RESOLVE');
    expect(mapped.message).toContain('DNS resolution failed');
  });

  it('maps EAI_AGAIN to EHTTPS_DNS_RESOLVE', () => {
    const err = makeNodeError('getaddrinfo EAI_AGAIN example.com', 'EAI_AGAIN');
    const mapped = mapError(err);

    expect(mapped.message).toContain('EHTTPS_DNS_RESOLVE');
  });

  it('maps ETIMEDOUT to EHTTPS_TIMEOUT', () => {
    const err = makeNodeError('connect ETIMEDOUT 1.2.3.4:443', 'ETIMEDOUT');
    const mapped = mapError(err);

    expect(mapped.message).toContain('EHTTPS_TIMEOUT');
    expect(mapped.message).toContain('Connection timed out');
  });

  it('maps ESOCKETTIMEDOUT to EHTTPS_TIMEOUT', () => {
    const err = makeNodeError('Socket timed out', 'ESOCKETTIMEDOUT');
    const mapped = mapError(err);

    expect(mapped.message).toContain('EHTTPS_TIMEOUT');
  });

  it('maps an error with PIN_MISMATCH in the message to EHTTPS_PIN_MISMATCH', () => {
    const err = new Error('PIN_MISMATCH: expected sha256/abc, got sha256/xyz');
    const mapped = mapError(err);

    expect(mapped.message).toContain('EHTTPS_PIN_MISMATCH');
  });

  it('maps an error with "pinning" in the message to EHTTPS_PIN_MISMATCH', () => {
    const err = new Error('Certificate pinning verification failed');
    const mapped = mapError(err);

    expect(mapped.message).toContain('EHTTPS_PIN_MISMATCH');
  });

  it('maps a CERT_HAS_EXPIRED error through getTlsErrorMessage to EHTTPS_CERT_EXPIRED', () => {
    const err = new Error('CERT_HAS_EXPIRED');
    const mapped = mapError(err);

    expect(mapped.message).toContain('EHTTPS_CERT_EXPIRED');
  });

  it('maps a generic certificate error through getTlsErrorMessage', () => {
    const err = new Error('certificate verification failed');
    const mapped = mapError(err);

    // The error message should contain one of the EHTTPS_CERT_* codes
    expect(mapped.message).toContain('EHTTPS_CERT_VERIFY');
  });

  it('returns a generic error as-is when no code or keyword matches', () => {
    const err = new Error('Something unexpected happened');
    const mapped = mapError(err);

    expect(mapped).toBe(err);
    expect(mapped.message).toBe('Something unexpected happened');
  });
});

// ---------------------------------------------------------------------------
// makeRequest — pure validation tests (no network)
// ---------------------------------------------------------------------------
describe('makeRequest', () => {
  it('throws when given an HTTP URL instead of HTTPS', async () => {
    const options = {
      method: 'GET' as const,
      url: 'http://example.com',
    };

    await expect(makeRequest(options, DEFAULT_CONFIG)).rejects.toThrow(
      'Only HTTPS URLs are supported'
    );
  });

  it('throws when given an FTP URL', async () => {
    const options = {
      method: 'GET' as const,
      url: 'ftp://files.example.com/readme.txt',
    };

    await expect(makeRequest(options, DEFAULT_CONFIG)).rejects.toThrow(
      'Only HTTPS URLs are supported'
    );
  });

  it('throws when given a protocol-relative URL (invalid URL)', async () => {
    const options = {
      method: 'GET' as const,
      url: '//example.com/path',
    };

    // The URL constructor will throw for protocol-relative URLs
    await expect(makeRequest(options, DEFAULT_CONFIG)).rejects.toThrow();
  });
});
