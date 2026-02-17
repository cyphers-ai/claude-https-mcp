import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as crypto from 'crypto';
import {
  validateTlsVersions,
  validateCiphers,
  loadCertificateFromFile,
  loadPrivateKeyFromFile,
  parsePkcs12,
  computeSpkiHash,
  verifyCertificatePin,
  getTlsErrorMessage,
} from '../tls/tls-utils.js';

vi.mock('fs');

// ---------------------------------------------------------------------------
// Static test certificate (self-signed EC P-256, CN=test, valid 10 years)
// Generated with:
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
//     -keyout /dev/null -out /dev/stdout -days 3650 -nodes -subj "/CN=test"
// ---------------------------------------------------------------------------
const TEST_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIBcjCCARmgAwIBAgIUGU2LHOO0Bq5h0nZq7sUntzB8itswCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yNjAyMTcxMzE0MDFaFw0zNjAyMTUxMzE0MDFa
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQuZq7o
xMSSIqg9eQa6ZEIwLX9c7mpN/XEJ4SzWDy/UnEcWNVkUshJULyRbZITzL8e+wmAo
4O5Gm9kSJPB++pLeo1MwUTAdBgNVHQ4EFgQUDTVZIyGkxE7p8Nyh4ypN18yw7Jkw
HwYDVR0jBBgwFoAUDTVZIyGkxE7p8Nyh4ypN18yw7JkwDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNHADBEAiBAoPyB59DLcjtOuRWON/mcr1ncOvJZxSUpBh1O
9iAWpwIgN4MOX5pHKwfEpq1kkKbj62spXVqOQHS821j141SEFGk=
-----END CERTIFICATE-----`;

const testCert = new crypto.X509Certificate(TEST_CERT_PEM);

// ---------------------------------------------------------------------------
// validateTlsVersions
// ---------------------------------------------------------------------------

describe('validateTlsVersions', () => {
  it('accepts TLSv1.2 to TLSv1.3', () => {
    expect(() => validateTlsVersions('TLSv1.2', 'TLSv1.3')).not.toThrow();
  });

  it('accepts TLSv1.2 to TLSv1.2', () => {
    expect(() => validateTlsVersions('TLSv1.2', 'TLSv1.2')).not.toThrow();
  });

  it('accepts TLSv1.3 to TLSv1.3', () => {
    expect(() => validateTlsVersions('TLSv1.3', 'TLSv1.3')).not.toThrow();
  });

  it('throws when min version is greater than max version', () => {
    expect(() => validateTlsVersions('TLSv1.3', 'TLSv1.2')).toThrow(
      'EHTTPS_TLS_HANDSHAKE',
    );
    expect(() => validateTlsVersions('TLSv1.3', 'TLSv1.2')).toThrow(
      'cannot be greater than maximum',
    );
  });

  it('throws for invalid minimum TLS version', () => {
    expect(() =>
      validateTlsVersions('TLSv1.0' as never, 'TLSv1.3'),
    ).toThrow('EHTTPS_TLS_HANDSHAKE');
    expect(() =>
      validateTlsVersions('TLSv1.0' as never, 'TLSv1.3'),
    ).toThrow('Invalid minimum TLS version');
  });

  it('throws for invalid maximum TLS version', () => {
    expect(() =>
      validateTlsVersions('TLSv1.2', 'TLSv1.4' as never),
    ).toThrow('EHTTPS_TLS_HANDSHAKE');
    expect(() =>
      validateTlsVersions('TLSv1.2', 'TLSv1.4' as never),
    ).toThrow('Invalid maximum TLS version');
  });
});

// ---------------------------------------------------------------------------
// validateCiphers
// ---------------------------------------------------------------------------

describe('validateCiphers', () => {
  it('returns the cipher string when valid for TLSv1.2', () => {
    const ciphers = 'ECDHE-RSA-AES128-GCM-SHA256';
    expect(validateCiphers(ciphers, 'TLSv1.2')).toBe(ciphers);
  });

  it('throws when cipher string is empty', () => {
    expect(() => validateCiphers('', 'TLSv1.2')).toThrow('EHTTPS_TLS_HANDSHAKE');
    expect(() => validateCiphers('', 'TLSv1.2')).toThrow('cannot be empty');
  });

  it('throws when cipher string is whitespace-only', () => {
    expect(() => validateCiphers('   ', 'TLSv1.2')).toThrow('cannot be empty');
  });

  it('accepts TLS_AES_256_GCM_SHA384 for TLSv1.3', () => {
    expect(validateCiphers('TLS_AES_256_GCM_SHA384', 'TLSv1.3')).toBe(
      'TLS_AES_256_GCM_SHA384',
    );
  });

  it('accepts TLS_CHACHA20_POLY1305_SHA256 for TLSv1.3', () => {
    expect(
      validateCiphers('TLS_CHACHA20_POLY1305_SHA256', 'TLSv1.3'),
    ).toBe('TLS_CHACHA20_POLY1305_SHA256');
  });

  it('accepts TLS_AES_128_GCM_SHA256 for TLSv1.3', () => {
    expect(validateCiphers('TLS_AES_128_GCM_SHA256', 'TLSv1.3')).toBe(
      'TLS_AES_128_GCM_SHA256',
    );
  });

  it('accepts a colon-separated list containing a TLS 1.3 cipher', () => {
    const ciphers = 'ECDHE-RSA-AES128-GCM-SHA256:TLS_AES_128_GCM_SHA256';
    expect(validateCiphers(ciphers, 'TLSv1.3')).toBe(ciphers);
  });

  it('throws when TLSv1.3 min but no TLS 1.3 cipher present', () => {
    expect(() =>
      validateCiphers('ECDHE-RSA-AES128-GCM-SHA256', 'TLSv1.3'),
    ).toThrow('EHTTPS_TLS_HANDSHAKE');
    expect(() =>
      validateCiphers('ECDHE-RSA-AES128-GCM-SHA256', 'TLSv1.3'),
    ).toThrow('must include TLS 1.3 ciphers');
  });

  it('does not require TLS 1.3 ciphers when minVersion is TLSv1.2', () => {
    expect(
      validateCiphers('ECDHE-RSA-AES128-GCM-SHA256', 'TLSv1.2'),
    ).toBe('ECDHE-RSA-AES128-GCM-SHA256');
  });
});

// ---------------------------------------------------------------------------
// loadCertificateFromFile
// ---------------------------------------------------------------------------

describe('loadCertificateFromFile', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('loads a certificate from an absolute path', () => {
    const certContent = Buffer.from('-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----');
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockReturnValue(certContent);

    const result = loadCertificateFromFile('/etc/ssl/cert.pem');
    expect(result).toEqual(certContent);
    expect(fs.readFileSync).toHaveBeenCalledWith('/etc/ssl/cert.pem');
  });

  it('throws when file does not exist', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    expect(() => loadCertificateFromFile('/nonexistent/cert.pem')).toThrow(
      'Failed to load certificate',
    );
  });

  it('includes original error message when file is not found', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    expect(() => loadCertificateFromFile('/nonexistent/cert.pem')).toThrow(
      'Certificate file not found',
    );
  });

  it('rejects paths containing null bytes', () => {
    expect(() => loadCertificateFromFile('/path/\0evil')).toThrow(
      'null bytes not allowed',
    );
  });

  it('rejects relative paths', () => {
    expect(() => loadCertificateFromFile('relative/cert.pem')).toThrow(
      'must be an absolute path',
    );
  });

  it('rejects relative path with dot prefix', () => {
    expect(() => loadCertificateFromFile('./relative/cert.pem')).toThrow(
      'must be an absolute path',
    );
  });
});

// ---------------------------------------------------------------------------
// loadPrivateKeyFromFile
// ---------------------------------------------------------------------------

describe('loadPrivateKeyFromFile', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('loads a private key from an absolute path', () => {
    const keyContent = Buffer.from('-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----');
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockReturnValue(keyContent);

    const result = loadPrivateKeyFromFile('/etc/ssl/key.pem');
    expect(result).toEqual(keyContent);
  });

  it('throws when file does not exist', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    expect(() => loadPrivateKeyFromFile('/nonexistent/key.pem')).toThrow(
      'Failed to load private key',
    );
  });

  it('includes original error message when file is not found', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    expect(() => loadPrivateKeyFromFile('/nonexistent/key.pem')).toThrow(
      'Private key file not found',
    );
  });

  it('rejects paths containing null bytes', () => {
    expect(() => loadPrivateKeyFromFile('/path/\0evil')).toThrow(
      'null bytes not allowed',
    );
  });

  it('rejects relative paths', () => {
    expect(() => loadPrivateKeyFromFile('relative/key.pem')).toThrow(
      'must be an absolute path',
    );
  });
});

// ---------------------------------------------------------------------------
// parsePkcs12
// ---------------------------------------------------------------------------

describe('parsePkcs12', () => {
  it('throws on empty buffer', () => {
    expect(() => parsePkcs12(Buffer.alloc(0), 'password')).toThrow();
  });

  it('throws on single-byte buffer (truncated ASN.1)', () => {
    expect(() => parsePkcs12(Buffer.from([0x30]), 'password')).toThrow();
  });

  it('throws on buffer with invalid ASN.1 structure (empty SEQUENCE)', () => {
    const invalidPkcs12 = Buffer.from([0x30, 0x00]);
    expect(() => parsePkcs12(invalidPkcs12, 'password')).toThrow(
      'Invalid PKCS#12 structure',
    );
  });

  it('throws on random data with SEQUENCE tag', () => {
    const randomData = crypto.randomBytes(64);
    randomData[0] = 0x30;
    expect(() => parsePkcs12(randomData, 'password')).toThrow();
  });

  it('includes openssl conversion hint or PKCS#12 in error message', () => {
    // Build a minimal SEQUENCE with two children, second will cause issues
    const buf = Buffer.from([
      0x30, 0x06, // SEQUENCE, length 6
      0x02, 0x01, 0x03, // INTEGER 3
      0x30, 0x01, 0x00, // SEQUENCE with one zero byte
    ]);
    try {
      parsePkcs12(buf, 'password');
      expect.unreachable('Expected parsePkcs12 to throw');
    } catch (error) {
      const msg = (error as Error).message;
      expect(
        msg.includes('PKCS#12') || msg.includes('openssl pkcs12'),
      ).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// computeSpkiHash
// ---------------------------------------------------------------------------

describe('computeSpkiHash', () => {
  it('returns a sha256/ prefixed hash string', () => {
    const hash = computeSpkiHash(TEST_CERT_PEM);
    expect(hash).toMatch(/^sha256\//);
  });

  it('returns a valid base64 hash after the prefix', () => {
    const hash = computeSpkiHash(TEST_CERT_PEM);
    const base64Part = hash.replace('sha256/', '');
    expect(base64Part.length).toBeGreaterThan(0);
    // Verify it is valid base64
    expect(() => Buffer.from(base64Part, 'base64')).not.toThrow();
    // SHA-256 produces 32 bytes
    expect(Buffer.from(base64Part, 'base64').length).toBe(32);
  });

  it('returns the same hash for the same certificate (deterministic)', () => {
    const hash1 = computeSpkiHash(TEST_CERT_PEM);
    const hash2 = computeSpkiHash(TEST_CERT_PEM);
    expect(hash1).toBe(hash2);
  });

  it('accepts a Buffer input', () => {
    const hash = computeSpkiHash(Buffer.from(TEST_CERT_PEM));
    expect(hash).toMatch(/^sha256\//);
  });

  it('produces the same hash regardless of string vs Buffer input', () => {
    const hashStr = computeSpkiHash(TEST_CERT_PEM);
    const hashBuf = computeSpkiHash(Buffer.from(TEST_CERT_PEM));
    expect(hashStr).toBe(hashBuf);
  });

  it('throws for invalid PEM input', () => {
    expect(() => computeSpkiHash('not a cert')).toThrow();
  });
});

// ---------------------------------------------------------------------------
// verifyCertificatePin
// ---------------------------------------------------------------------------

describe('verifyCertificatePin', () => {
  it('returns invalid when certificate chain is empty', () => {
    const result = verifyCertificatePin([], ['sha256/abc'], 'leaf');
    expect(result.valid).toBe(false);
    expect(result.error).toBe('No certificates in chain');
  });

  it('validates leaf mode with matching sha256 pin', () => {
    const hash = computeSpkiHash(TEST_CERT_PEM);
    const result = verifyCertificatePin([testCert], [hash], 'leaf');
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('fails leaf mode with non-matching pin', () => {
    const result = verifyCertificatePin(
      [testCert],
      ['sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa='],
      'leaf',
    );
    expect(result.valid).toBe(false);
    expect(result.error).toContain('EHTTPS_PIN_MISMATCH');
  });

  it('returns error for intermediate mode with single cert chain', () => {
    const result = verifyCertificatePin([testCert], ['sha256/abc'], 'intermediate');
    expect(result.valid).toBe(false);
    expect(result.error).toBe('No intermediate certificate in chain');
  });

  it('validates root mode (uses last cert in chain)', () => {
    const hash = computeSpkiHash(TEST_CERT_PEM);
    // Single-cert chain: root is the same as leaf
    const result = verifyCertificatePin([testCert], [hash], 'root');
    expect(result.valid).toBe(true);
  });

  it('validates spki mode (checks all certs in chain)', () => {
    const hash = computeSpkiHash(TEST_CERT_PEM);
    const result = verifyCertificatePin([testCert], [hash], 'spki');
    expect(result.valid).toBe(true);
  });

  it('fails spki mode when no cert matches', () => {
    const result = verifyCertificatePin(
      [testCert],
      ['sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa='],
      'spki',
    );
    expect(result.valid).toBe(false);
    expect(result.error).toContain('EHTTPS_PIN_MISMATCH');
    expect(result.error).toContain('No certificate in chain matches');
  });

  it('validates leaf mode with PEM pin (BEGIN CERTIFICATE format)', () => {
    const result = verifyCertificatePin([testCert], [TEST_CERT_PEM], 'leaf');
    expect(result.valid).toBe(true);
  });

  it('ignores invalid PEM pins without throwing', () => {
    const result = verifyCertificatePin(
      [testCert],
      ['-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----'],
      'leaf',
    );
    // Invalid PEM is skipped, so no match is found
    expect(result.valid).toBe(false);
    expect(result.error).toContain('EHTTPS_PIN_MISMATCH');
  });

  it('returns error for unknown pinning mode', () => {
    const result = verifyCertificatePin(
      [testCert],
      ['sha256/abc'],
      'unknown' as never,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Unknown pinning mode');
  });
});

// ---------------------------------------------------------------------------
// getTlsErrorMessage
// ---------------------------------------------------------------------------

describe('getTlsErrorMessage', () => {
  it('maps CERT_HAS_EXPIRED to EHTTPS_CERT_EXPIRED', () => {
    const msg = getTlsErrorMessage(new Error('CERT_HAS_EXPIRED'));
    expect(msg).toContain('EHTTPS_CERT_EXPIRED');
    expect(msg).toContain('certificate has expired');
  });

  it('maps CERT_NOT_YET_VALID to EHTTPS_CERT_NOT_YET_VALID', () => {
    const msg = getTlsErrorMessage(new Error('CERT_NOT_YET_VALID'));
    expect(msg).toContain('EHTTPS_CERT_NOT_YET_VALID');
    expect(msg).toContain('not yet valid');
  });

  it('maps UNABLE_TO_VERIFY_LEAF_SIGNATURE to EHTTPS_CERT_VERIFY', () => {
    const msg = getTlsErrorMessage(
      new Error('UNABLE_TO_VERIFY_LEAF_SIGNATURE'),
    );
    expect(msg).toContain('EHTTPS_CERT_VERIFY');
    expect(msg).toContain('Unable to verify certificate');
  });

  it('maps SELF_SIGNED_CERT_IN_CHAIN to EHTTPS_CERT_VERIFY', () => {
    const msg = getTlsErrorMessage(
      new Error('SELF_SIGNED_CERT_IN_CHAIN'),
    );
    expect(msg).toContain('EHTTPS_CERT_VERIFY');
    expect(msg).toContain('Unable to verify certificate');
  });

  it('maps HOSTNAME_MISMATCH to EHTTPS_HOSTNAME_MISMATCH', () => {
    const msg = getTlsErrorMessage(new Error('HOSTNAME_MISMATCH'));
    expect(msg).toContain('EHTTPS_HOSTNAME_MISMATCH');
    expect(msg).toContain('hostname mismatch');
  });

  it('maps ERR_TLS_CERT_ALTNAME_INVALID to EHTTPS_HOSTNAME_MISMATCH', () => {
    const msg = getTlsErrorMessage(
      new Error('ERR_TLS_CERT_ALTNAME_INVALID'),
    );
    expect(msg).toContain('EHTTPS_HOSTNAME_MISMATCH');
  });

  it('maps DEPTH_ZERO_SELF_SIGNED_CERT to EHTTPS_CERT_VERIFY', () => {
    const msg = getTlsErrorMessage(
      new Error('DEPTH_ZERO_SELF_SIGNED_CERT'),
    );
    expect(msg).toContain('EHTTPS_CERT_VERIFY');
    expect(msg).toContain('Self-signed certificate not trusted');
  });

  it('maps CERT_REVOKED to EHTTPS_CERT_REVOKED', () => {
    const msg = getTlsErrorMessage(new Error('CERT_REVOKED'));
    expect(msg).toContain('EHTTPS_CERT_REVOKED');
    expect(msg).toContain('has been revoked');
  });

  it('maps handshake errors to EHTTPS_TLS_HANDSHAKE', () => {
    const msg = getTlsErrorMessage(new Error('TLS handshake failed'));
    expect(msg).toContain('EHTTPS_TLS_HANDSHAKE');
    expect(msg).toContain('TLS handshake failed');
  });

  it('maps SSL errors to EHTTPS_TLS_HANDSHAKE', () => {
    const msg = getTlsErrorMessage(new Error('SSL routines failed'));
    expect(msg).toContain('EHTTPS_TLS_HANDSHAKE');
  });

  it('falls back to EHTTPS_CERT_VERIFY for unknown errors', () => {
    const msg = getTlsErrorMessage(new Error('something unexpected'));
    expect(msg).toContain('EHTTPS_CERT_VERIFY');
    expect(msg).toContain('something unexpected');
  });
});
