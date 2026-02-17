import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fs from 'fs';
import { getCaCertificates } from '../tls/ca-utils.js';

vi.mock('fs');

describe('getCaCertificates', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe('bundled mode', () => {
    it('loads bundled CA file', () => {
      const fakeCA = Buffer.from('-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----');
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(fakeCA);

      const result = getCaCertificates('bundled');
      expect(Buffer.isBuffer(result)).toBe(true);
      expect(result).toEqual(fakeCA);
    });

    it('falls back to cwd path when installed path missing', () => {
      const fakeCA = Buffer.from('fallback-ca');
      vi.mocked(fs.existsSync).mockReturnValueOnce(false).mockReturnValueOnce(true);
      vi.mocked(fs.readFileSync).mockReturnValue(fakeCA);

      const result = getCaCertificates('bundled');
      expect(result).toEqual(fakeCA);
    });

    it('throws when bundled CA file not found', () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);
      expect(() => getCaCertificates('bundled')).toThrow('EHTTPS_CA_LOAD_FAILED');
    });
  });

  describe('osPlusBundled mode', () => {
    it('loads bundled CA (OS CAs added by Node.js)', () => {
      const fakeCA = Buffer.from('bundled-ca');
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(fakeCA);

      const result = getCaCertificates('osPlusBundled');
      expect(Buffer.isBuffer(result)).toBe(true);
    });
  });

  describe('osOnly mode', () => {
    it('returns empty array (delegates to Node.js defaults)', () => {
      const result = getCaCertificates('osOnly');
      expect(result).toEqual([]);
    });
  });

  describe('custom mode', () => {
    it('loads CA files from custom paths', () => {
      const fakeCA = Buffer.from('custom-ca');
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(fakeCA);

      const result = getCaCertificates('custom', ['/path/to/ca.pem']);
      expect(Buffer.isBuffer(result)).toBe(true);
      expect(result).toEqual(fakeCA);
    });

    it('throws when no custom paths provided', () => {
      expect(() => getCaCertificates('custom', [])).toThrow('EHTTPS_CA_LOAD_FAILED');
    });

    it('throws when custom paths is undefined', () => {
      expect(() => getCaCertificates('custom')).toThrow('EHTTPS_CA_LOAD_FAILED');
    });

    it('loads multiple custom CA files', () => {
      const fakeCA1 = Buffer.from('ca1');
      const fakeCA2 = Buffer.from('ca2');
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync)
        .mockReturnValueOnce(fakeCA1)
        .mockReturnValueOnce(fakeCA2);

      const result = getCaCertificates('custom', ['/path/ca1.pem', '/path/ca2.pem']);
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(2);
    });

    it('throws when custom CA file not found', () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);
      expect(() => getCaCertificates('custom', ['/missing/ca.pem'])).toThrow('EHTTPS_CA_LOAD_FAILED');
    });

    it('rejects paths with null bytes', () => {
      expect(() => getCaCertificates('custom', ['/path/to\0/ca.pem'])).toThrow('null bytes');
    });

    it('rejects relative paths', () => {
      expect(() => getCaCertificates('custom', ['relative/ca.pem'])).toThrow('absolute path');
    });
  });

  describe('additionalCaPaths', () => {
    it('appends additional CAs to bundled mode', () => {
      const bundledCA = Buffer.from('bundled');
      const additionalCA = Buffer.from('additional');
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync)
        .mockReturnValueOnce(bundledCA)
        .mockReturnValueOnce(additionalCA);

      const result = getCaCertificates('bundled', [], ['/additional/ca.pem']);
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(2);
    });

    it('adds additional CAs to osOnly mode', () => {
      const additionalCA = Buffer.from('additional');
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(additionalCA);

      const result = getCaCertificates('osOnly', [], ['/additional/ca.pem']);
      expect(Buffer.isBuffer(result)).toBe(true);
      expect(result).toEqual(additionalCA);
    });
  });
});
