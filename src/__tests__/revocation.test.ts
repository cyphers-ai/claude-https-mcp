import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import {
  clearRevocationCache,
  extractOcspUrl,
  extractCrlUrls,
  checkOcspStapling,
  checkOcsp,
  checkCrl,
  checkRevocation,
  OcspStatus,
} from '../tls/revocation.js';
import type { RevocationConfig } from '../config/types.js';

// ---------------------------------------------------------------------------
// Mock http and https modules at the top level for ESM compatibility
// ---------------------------------------------------------------------------
vi.mock('http', async (importOriginal) => {
  const actual = await importOriginal<typeof import('http')>();
  return {
    ...actual,
    request: vi.fn(),
  };
});

vi.mock('https', async (importOriginal) => {
  const actual = await importOriginal<typeof import('https')>();
  return {
    ...actual,
    request: vi.fn(),
  };
});

// Import the mocked modules after vi.mock declarations
import * as http from 'http';
import * as https from 'https';

const mockedHttpRequest = vi.mocked(http.request);
const mockedHttpsRequest = vi.mocked(https.request);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMockCert(overrides: Record<string, unknown> = {}): crypto.X509Certificate {
  return {
    infoAccess: 'OCSP - URI:http://ocsp.example.com\nCA Issuers - URI:http://ca.example.com/ca.crt',
    serialNumber: 'ABC123',
    subject: 'CN=test',
    toString: () =>
      'Certificate:\n  Data:\n    Full Name:\n      URI:http://crl.example.com/ca.crl\n',
    publicKey: { export: () => Buffer.alloc(32) },
    ...overrides,
  } as unknown as crypto.X509Certificate;
}

function makeMockIssuerCert(overrides: Record<string, unknown> = {}): crypto.X509Certificate {
  return {
    subject: 'CN=IssuerCA',
    serialNumber: 'ISSUER001',
    publicKey: {
      export: () => Buffer.alloc(32),
    },
    ...overrides,
  } as unknown as crypto.X509Certificate;
}

function makeRevocationConfig(overrides: Partial<RevocationConfig> = {}): RevocationConfig {
  return {
    enabled: true,
    policy: 'ocspWithCrlFallback',
    failMode: 'soft',
    customOcspUrl: null,
    customCrlUrl: null,
    enableStapling: false,
    cacheTtlSeconds: 300,
    ...overrides,
  };
}

/**
 * Build a minimal Buffer that parseOcspResponse recognises as GOOD.
 * The scanner looks for the two-byte sequence [0x80, 0x00].
 */
function buildGoodOcspBuffer(): Buffer {
  const buf = Buffer.alloc(12);
  buf[5] = 0x80;
  buf[6] = 0x00;
  return buf;
}

/**
 * Build a minimal Buffer recognised as REVOKED (byte 0xa1).
 */
function buildRevokedOcspBuffer(): Buffer {
  const buf = Buffer.alloc(12);
  buf[5] = 0xa1;
  return buf;
}

/**
 * Build a minimal Buffer recognised as UNKNOWN ([0x82, 0x00]).
 */
function buildUnknownOcspBuffer(): Buffer {
  const buf = Buffer.alloc(12);
  buf[5] = 0x82;
  buf[6] = 0x00;
  return buf;
}

/**
 * Create a mock HTTP response stream that emits the given body and status.
 */
function createMockHttpResponse(statusCode: number, body: Buffer): EventEmitter {
  const res = new EventEmitter() as EventEmitter & { statusCode: number };
  res.statusCode = statusCode;
  process.nextTick(() => {
    res.emit('data', body);
    res.emit('end');
  });
  return res;
}

/**
 * Configure the mocked http.request to respond with the given status and body.
 * Supports multiple sequential calls with different responses via an array.
 */
function setupMockHttpRequest(statusCode: number, body: Buffer): void {
  mockedHttpRequest.mockImplementation((_opts: unknown, cb: unknown) => {
    const req = new EventEmitter() as EventEmitter & {
      write: ReturnType<typeof vi.fn>;
      end: ReturnType<typeof vi.fn>;
      destroy: ReturnType<typeof vi.fn>;
    };
    req.write = vi.fn();
    req.end = vi.fn();
    req.destroy = vi.fn();

    process.nextTick(() => {
      (cb as (res: EventEmitter) => void)(createMockHttpResponse(statusCode, body));
    });

    return req as unknown as http.ClientRequest;
  });
}

/**
 * Configure sequential responses: each call to http.request returns the next
 * response in the array.
 */
function setupMockHttpRequestSequence(responses: Array<{ statusCode: number; body: Buffer }>): void {
  let callIndex = 0;
  mockedHttpRequest.mockImplementation((_opts: unknown, cb: unknown) => {
    const { statusCode, body } = responses[callIndex] ?? responses[responses.length - 1];
    callIndex++;

    const req = new EventEmitter() as EventEmitter & {
      write: ReturnType<typeof vi.fn>;
      end: ReturnType<typeof vi.fn>;
      destroy: ReturnType<typeof vi.fn>;
    };
    req.write = vi.fn();
    req.end = vi.fn();
    req.destroy = vi.fn();

    process.nextTick(() => {
      (cb as (res: EventEmitter) => void)(createMockHttpResponse(statusCode, body));
    });

    return req as unknown as http.ClientRequest;
  });
}

/**
 * Configure http.request to emit a network error.
 */
function setupMockHttpRequestError(errorMessage: string): void {
  mockedHttpRequest.mockImplementation((_opts: unknown, _cb: unknown) => {
    const req = new EventEmitter() as EventEmitter & {
      write: ReturnType<typeof vi.fn>;
      end: ReturnType<typeof vi.fn>;
      destroy: ReturnType<typeof vi.fn>;
    };
    req.write = vi.fn();
    req.end = vi.fn();
    req.destroy = vi.fn();

    process.nextTick(() => {
      req.emit('error', new Error(errorMessage));
    });

    return req as unknown as http.ClientRequest;
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('revocation', () => {
  beforeEach(() => {
    clearRevocationCache();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // =========================================================================
  // extractOcspUrl
  // =========================================================================
  describe('extractOcspUrl', () => {
    it('extracts the OCSP URL from a certificate with standard infoAccess', () => {
      const cert = makeMockCert();
      expect(extractOcspUrl(cert)).toBe('http://ocsp.example.com');
    });

    it('returns undefined when infoAccess is missing', () => {
      const cert = makeMockCert({ infoAccess: undefined });
      expect(extractOcspUrl(cert)).toBeUndefined();
    });

    it('returns undefined when infoAccess is an empty string', () => {
      const cert = makeMockCert({ infoAccess: '' });
      expect(extractOcspUrl(cert)).toBeUndefined();
    });

    it('returns undefined when no OCSP entry is present in infoAccess', () => {
      const cert = makeMockCert({
        infoAccess: 'CA Issuers - URI:http://ca.example.com/ca.crt',
      });
      expect(extractOcspUrl(cert)).toBeUndefined();
    });

    it('extracts the first OCSP URL when multiple entries exist', () => {
      const cert = makeMockCert({
        infoAccess:
          'OCSP - URI:http://ocsp1.example.com\nOCSP - URI:http://ocsp2.example.com',
      });
      expect(extractOcspUrl(cert)).toBe('http://ocsp1.example.com');
    });

    it('trims whitespace from the extracted URL', () => {
      const cert = makeMockCert({
        infoAccess: 'OCSP - URI:  http://ocsp.example.com  ',
      });
      expect(extractOcspUrl(cert)).toBe('http://ocsp.example.com');
    });

    it('returns undefined gracefully when accessing infoAccess throws', () => {
      const cert = {
        get infoAccess(): string {
          throw new Error('boom');
        },
      } as unknown as crypto.X509Certificate;
      expect(extractOcspUrl(cert)).toBeUndefined();
    });
  });

  // =========================================================================
  // extractCrlUrls
  // =========================================================================
  describe('extractCrlUrls', () => {
    it('extracts CRL URLs from a certificate toString output', () => {
      const cert = makeMockCert();
      const urls = extractCrlUrls(cert);
      expect(urls).toEqual(['http://crl.example.com/ca.crl']);
    });

    it('returns an empty array when no CRL URL matches', () => {
      const cert = makeMockCert({
        toString: () => 'Certificate:\n  No CRL here\n',
      });
      expect(extractCrlUrls(cert)).toEqual([]);
    });

    it('extracts multiple CRL URLs', () => {
      const cert = makeMockCert({
        toString: () =>
          'URI:http://crl1.example.com/root.crl\nURI:https://crl2.example.com/inter.crl',
      });
      const urls = extractCrlUrls(cert);
      expect(urls).toHaveLength(2);
      expect(urls).toContain('http://crl1.example.com/root.crl');
      expect(urls).toContain('https://crl2.example.com/inter.crl');
    });

    it('ignores URIs that do not end with .crl', () => {
      const cert = makeMockCert({
        toString: () => 'URI:http://example.com/not-a-crl.pem',
      });
      expect(extractCrlUrls(cert)).toEqual([]);
    });

    it('returns empty array when toString throws', () => {
      const cert = {
        toString: () => {
          throw new Error('boom');
        },
      } as unknown as crypto.X509Certificate;
      expect(extractCrlUrls(cert)).toEqual([]);
    });

    it('handles https CRL URLs correctly', () => {
      const cert = makeMockCert({
        toString: () => 'URI:https://secure-crl.example.com/ca.crl',
      });
      expect(extractCrlUrls(cert)).toEqual(['https://secure-crl.example.com/ca.crl']);
    });
  });

  // =========================================================================
  // checkOcspStapling
  // =========================================================================
  describe('checkOcspStapling', () => {
    it('returns skipped when no stapled response is provided', () => {
      const result = checkOcspStapling(undefined);
      expect(result.checked).toBe(false);
      expect(result.method).toBe('ocsp-stapling');
      expect(result.status).toBe('skipped');
      expect(result.error).toBeDefined();
    });

    it('returns skipped when stapled response is an empty buffer', () => {
      const result = checkOcspStapling(Buffer.alloc(0));
      expect(result.checked).toBe(false);
      expect(result.status).toBe('skipped');
    });

    it('detects GOOD status from stapled response', () => {
      const result = checkOcspStapling(buildGoodOcspBuffer());
      expect(result.checked).toBe(true);
      expect(result.revoked).toBe(false);
      expect(result.method).toBe('ocsp-stapling');
      expect(result.status).toBe(OcspStatus.GOOD);
    });

    it('detects REVOKED status from stapled response', () => {
      const result = checkOcspStapling(buildRevokedOcspBuffer());
      expect(result.checked).toBe(true);
      expect(result.revoked).toBe(true);
      expect(result.method).toBe('ocsp-stapling');
      expect(result.status).toBe(OcspStatus.REVOKED);
    });

    it('detects UNKNOWN status from stapled response', () => {
      const result = checkOcspStapling(buildUnknownOcspBuffer());
      expect(result.checked).toBe(true);
      expect(result.revoked).toBe(false);
      expect(result.status).toBe(OcspStatus.UNKNOWN);
    });

    it('returns UNKNOWN for a buffer shorter than 10 bytes', () => {
      const shortBuf = Buffer.alloc(5);
      const result = checkOcspStapling(shortBuf);
      expect(result.checked).toBe(true);
      expect(result.revoked).toBe(false);
      expect(result.status).toBe(OcspStatus.UNKNOWN);
    });

    it('returns UNKNOWN when buffer has no recognisable pattern', () => {
      const noiseBuf = Buffer.alloc(20, 0x01);
      const result = checkOcspStapling(noiseBuf);
      expect(result.checked).toBe(true);
      expect(result.revoked).toBe(false);
      expect(result.status).toBe(OcspStatus.UNKNOWN);
    });

    it('detects GOOD when the pattern appears later in the buffer', () => {
      const buf = Buffer.alloc(30, 0x01);
      buf[20] = 0x80;
      buf[21] = 0x00;
      const result = checkOcspStapling(buf);
      expect(result.status).toBe(OcspStatus.GOOD);
    });

    it('REVOKED takes priority when 0xa1 appears before GOOD bytes', () => {
      const buf = Buffer.alloc(30, 0x01);
      buf[5] = 0xa1;  // REVOKED at position 5
      buf[20] = 0x80; // GOOD at position 20
      buf[21] = 0x00;
      const result = checkOcspStapling(buf);
      expect(result.status).toBe(OcspStatus.REVOKED);
    });
  });

  // =========================================================================
  // clearRevocationCache
  // =========================================================================
  describe('clearRevocationCache', () => {
    it('does not throw when called on an empty cache', () => {
      expect(() => clearRevocationCache()).not.toThrow();
    });

    it('clears cached OCSP results so subsequent calls hit the network again', async () => {
      const goodBody = buildGoodOcspBuffer();
      setupMockHttpRequest(200, goodBody);

      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();

      // First call populates cache
      const r1 = await checkOcsp(cert, issuer, 'http://ocsp.example.com', 5000, 300);
      expect(r1.cached).toBeUndefined();

      // Second call should be cached
      const r2 = await checkOcsp(cert, issuer, 'http://ocsp.example.com', 5000, 300);
      expect(r2.cached).toBe(true);

      // Clear cache
      clearRevocationCache();

      // Third call should hit network again
      const r3 = await checkOcsp(cert, issuer, 'http://ocsp.example.com', 5000, 300);
      expect(r3.cached).toBeUndefined();

      // http.request was called twice (first and third call; second was cached)
      expect(mockedHttpRequest).toHaveBeenCalledTimes(2);
    });
  });

  // =========================================================================
  // checkOcsp (network-dependent, mocked)
  // =========================================================================
  describe('checkOcsp', () => {
    it('returns GOOD when OCSP responder returns a GOOD response', async () => {
      setupMockHttpRequest(200, buildGoodOcspBuffer());

      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();
      const result = await checkOcsp(cert, issuer, 'http://ocsp.example.com');

      expect(result.checked).toBe(true);
      expect(result.revoked).toBe(false);
      expect(result.method).toBe('ocsp');
      expect(result.status).toBe(OcspStatus.GOOD);
      expect(result.ocspUrl).toBe('http://ocsp.example.com');
    });

    it('returns REVOKED when OCSP responder returns a REVOKED response', async () => {
      setupMockHttpRequest(200, buildRevokedOcspBuffer());

      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();
      const result = await checkOcsp(cert, issuer, 'http://ocsp.example.com');

      expect(result.checked).toBe(true);
      expect(result.revoked).toBe(true);
      expect(result.status).toBe(OcspStatus.REVOKED);
    });

    it('returns skipped when no OCSP URL is available', async () => {
      const cert = makeMockCert({ infoAccess: undefined });
      const issuer = makeMockIssuerCert();
      const result = await checkOcsp(cert, issuer);

      expect(result.checked).toBe(false);
      expect(result.status).toBe('skipped');
      expect(result.error).toContain('No OCSP responder URL');
    });

    it('returns error when the OCSP responder returns non-200', async () => {
      setupMockHttpRequest(500, Buffer.alloc(0));

      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();
      const result = await checkOcsp(cert, issuer, 'http://ocsp.example.com');

      expect(result.checked).toBe(false);
      expect(result.status).toBe('error');
      expect(result.error).toContain('status 500');
    });

    it('returns error when http.request emits a network error', async () => {
      setupMockHttpRequestError('connection refused');

      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();
      const result = await checkOcsp(cert, issuer, 'http://ocsp.example.com');

      expect(result.checked).toBe(false);
      expect(result.status).toBe('error');
      expect(result.error).toContain('connection refused');
    });

    it('uses the custom OCSP URL when provided', async () => {
      setupMockHttpRequest(200, buildGoodOcspBuffer());

      const cert = makeMockCert({ infoAccess: undefined });
      const issuer = makeMockIssuerCert();
      const result = await checkOcsp(cert, issuer, 'http://custom-ocsp.example.com');

      expect(result.checked).toBe(true);
      expect(result.ocspUrl).toBe('http://custom-ocsp.example.com');
    });

    it('returns cached result on second call', async () => {
      setupMockHttpRequest(200, buildGoodOcspBuffer());

      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();

      await checkOcsp(cert, issuer, 'http://ocsp.example.com', 5000, 300);
      const cached = await checkOcsp(cert, issuer, 'http://ocsp.example.com', 5000, 300);

      expect(cached.cached).toBe(true);
      expect(cached.status).toBe(OcspStatus.GOOD);
      expect(mockedHttpRequest).toHaveBeenCalledTimes(1);
    });

    it('bypasses cache when cacheTtl is zero', async () => {
      setupMockHttpRequest(200, buildGoodOcspBuffer());

      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();

      await checkOcsp(cert, issuer, 'http://ocsp.example.com', 5000, 0);
      const second = await checkOcsp(cert, issuer, 'http://ocsp.example.com', 5000, 0);

      expect(second.cached).toBeUndefined();
      expect(mockedHttpRequest).toHaveBeenCalledTimes(2);
    });
  });

  // =========================================================================
  // checkCrl (network-dependent, mocked)
  // =========================================================================
  describe('checkCrl', () => {
    it('returns crl-valid when the serial is not in the CRL', async () => {
      const crlBody = Buffer.alloc(64, 0x00);
      setupMockHttpRequest(200, crlBody);

      const cert = makeMockCert();
      const result = await checkCrl(cert, 'http://crl.example.com/ca.crl');

      expect(result.checked).toBe(true);
      expect(result.revoked).toBe(false);
      expect(result.method).toBe('crl');
      expect(result.status).toBe('crl-valid');
    });

    it('returns crl-revoked when the serial IS found in the CRL', async () => {
      // Embed the serial number ABC123 (hex) into a CRL-like buffer.
      const serialBytes = Buffer.from('ABC123', 'hex');
      const crlBody = Buffer.alloc(64, 0x00);
      const offset = 10;
      crlBody[offset] = 0x02;
      crlBody[offset + 1] = serialBytes.length;
      serialBytes.copy(crlBody, offset + 2);

      setupMockHttpRequest(200, crlBody);

      const cert = makeMockCert();
      const result = await checkCrl(cert, 'http://crl.example.com/ca.crl');

      expect(result.checked).toBe(true);
      expect(result.revoked).toBe(true);
      expect(result.status).toBe('crl-revoked');
    });

    it('returns skipped when no CRL URL is available', async () => {
      const cert = makeMockCert({ toString: () => 'no crl urls here' });
      const result = await checkCrl(cert);

      expect(result.checked).toBe(false);
      expect(result.status).toBe('skipped');
      expect(result.error).toContain('No CRL distribution points');
    });

    it('returns error when all CRL downloads fail', async () => {
      setupMockHttpRequest(503, Buffer.alloc(0));

      const cert = makeMockCert();
      const result = await checkCrl(cert, 'http://crl.example.com/ca.crl');

      expect(result.checked).toBe(false);
      expect(result.status).toBe('error');
    });
  });

  // =========================================================================
  // checkRevocation (policy orchestration)
  // =========================================================================
  describe('checkRevocation', () => {
    // -- OCSP stapling tests -----------------------------------------------
    it('returns stapled GOOD result immediately when stapling is enabled', async () => {
      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({ enableStapling: true });
      const stapled = buildGoodOcspBuffer();

      const result = await checkRevocation(cert, issuer, config, 5000, stapled);

      expect(result.method).toBe('ocsp-stapling');
      expect(result.status).toBe(OcspStatus.GOOD);
      expect(result.checked).toBe(true);
      expect(result.revoked).toBe(false);
    });

    it('returns stapled REVOKED result immediately when stapling detects revocation', async () => {
      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({ enableStapling: true });
      const stapled = buildRevokedOcspBuffer();

      const result = await checkRevocation(cert, issuer, config, 5000, stapled);

      expect(result.method).toBe('ocsp-stapling');
      expect(result.revoked).toBe(true);
    });

    it('falls through stapling when it is disabled even if stapled response is provided', async () => {
      setupMockHttpRequest(200, buildGoodOcspBuffer());

      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({ enableStapling: false });
      const stapled = buildGoodOcspBuffer();

      const result = await checkRevocation(cert, issuer, config, 5000, stapled);
      expect(result.method).toBe('ocsp');
    });

    // -- ocspOnly policy ---------------------------------------------------
    it('ocspOnly: returns OCSP result on success', async () => {
      setupMockHttpRequest(200, buildGoodOcspBuffer());

      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({ policy: 'ocspOnly' });

      const result = await checkRevocation(cert, issuer, config);
      expect(result.method).toBe('ocsp');
      expect(result.status).toBe(OcspStatus.GOOD);
    });

    it('ocspOnly hard-fail: throws when OCSP check fails', async () => {
      const cert = makeMockCert({ infoAccess: undefined });
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({ policy: 'ocspOnly', failMode: 'hard' });

      await expect(checkRevocation(cert, issuer, config)).rejects.toThrow('hard-fail');
    });

    it('ocspOnly soft-fail: returns error result without throwing', async () => {
      const cert = makeMockCert({ infoAccess: undefined });
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({ policy: 'ocspOnly', failMode: 'soft' });

      const result = await checkRevocation(cert, issuer, config);
      expect(result.checked).toBe(false);
      expect(result.status).toBe('skipped');
    });

    // -- crlOnly policy ----------------------------------------------------
    it('crlOnly: returns CRL result on success', async () => {
      const crlBody = Buffer.alloc(64, 0x00);
      setupMockHttpRequest(200, crlBody);

      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({ policy: 'crlOnly' });

      const result = await checkRevocation(cert, issuer, config);
      expect(result.method).toBe('crl');
      expect(result.status).toBe('crl-valid');
    });

    it('crlOnly hard-fail: throws when CRL check fails', async () => {
      const cert = makeMockCert({ toString: () => 'no crl urls' });
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({ policy: 'crlOnly', failMode: 'hard' });

      await expect(checkRevocation(cert, issuer, config)).rejects.toThrow('hard-fail');
    });

    // -- ocspWithCrlFallback policy ----------------------------------------
    it('ocspWithCrlFallback: returns OCSP result when OCSP succeeds', async () => {
      setupMockHttpRequest(200, buildGoodOcspBuffer());

      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({ policy: 'ocspWithCrlFallback' });

      const result = await checkRevocation(cert, issuer, config);
      expect(result.method).toBe('ocsp');
      expect(result.status).toBe(OcspStatus.GOOD);
    });

    it('ocspWithCrlFallback: falls back to CRL when OCSP has no URL', async () => {
      const crlBody = Buffer.alloc(64, 0x00);
      setupMockHttpRequest(200, crlBody);

      const cert = makeMockCert({ infoAccess: undefined });
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({
        policy: 'ocspWithCrlFallback',
        customCrlUrl: 'http://crl.example.com/ca.crl',
      });

      const result = await checkRevocation(cert, issuer, config);
      expect(result.method).toBe('crl');
      expect(result.status).toBe('crl-valid');
    });

    it('ocspWithCrlFallback hard-fail: throws when both OCSP and CRL fail', async () => {
      const cert = makeMockCert({ infoAccess: undefined, toString: () => 'no crl' });
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({ policy: 'ocspWithCrlFallback', failMode: 'hard' });

      await expect(checkRevocation(cert, issuer, config)).rejects.toThrow('hard-fail');
    });

    // -- bothRequired policy -----------------------------------------------
    it('bothRequired: returns GOOD when both OCSP and CRL succeed', async () => {
      const goodBody = buildGoodOcspBuffer();
      const crlBody = Buffer.alloc(64, 0x00);

      setupMockHttpRequestSequence([
        { statusCode: 200, body: goodBody },
        { statusCode: 200, body: crlBody },
      ]);

      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({
        policy: 'bothRequired',
        customCrlUrl: 'http://crl.example.com/ca.crl',
      });

      const result = await checkRevocation(cert, issuer, config);
      expect(result.checked).toBe(true);
      expect(result.revoked).toBe(false);
      expect(result.status).toBe(OcspStatus.GOOD);
    });

    it('bothRequired hard-fail: throws when OCSP succeeds but CRL fails', async () => {
      setupMockHttpRequest(200, buildGoodOcspBuffer());

      const cert = makeMockCert({ toString: () => 'no crl' });
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({ policy: 'bothRequired', failMode: 'hard' });

      await expect(checkRevocation(cert, issuer, config)).rejects.toThrow('hard-fail');
    });

    it('bothRequired soft-fail: returns error status when not all checks complete', async () => {
      setupMockHttpRequest(200, buildGoodOcspBuffer());

      const cert = makeMockCert({ toString: () => 'no crl' });
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({ policy: 'bothRequired', failMode: 'soft' });

      const result = await checkRevocation(cert, issuer, config);
      expect(result.checked).toBe(false);
      expect(result.status).toBe('error');
    });

    // -- null issuerCert ---------------------------------------------------
    it('skips OCSP when issuerCert is null', async () => {
      const crlBody = Buffer.alloc(64, 0x00);
      setupMockHttpRequest(200, crlBody);

      const cert = makeMockCert();
      const config = makeRevocationConfig({
        policy: 'ocspWithCrlFallback',
        customCrlUrl: 'http://crl.example.com/ca.crl',
      });

      const result = await checkRevocation(cert, null, config);
      expect(result.method).toBe('crl');
    });

    // -- revoked via OCSP short-circuits -----------------------------------
    it('returns immediately when OCSP detects revocation (no CRL check)', async () => {
      setupMockHttpRequest(200, buildRevokedOcspBuffer());

      const cert = makeMockCert();
      const issuer = makeMockIssuerCert();
      const config = makeRevocationConfig({
        policy: 'bothRequired',
        customCrlUrl: 'http://crl.example.com/ca.crl',
      });

      const result = await checkRevocation(cert, issuer, config);
      expect(result.revoked).toBe(true);
      expect(result.method).toBe('ocsp');
      // Only one HTTP call (for OCSP); CRL was never checked
      expect(mockedHttpRequest).toHaveBeenCalledTimes(1);
    });
  });
});
