import { describe, it, expect, beforeEach } from 'vitest';
import {
  validateLicense,
  isProFeatureEnabled,
  hasProLicense,
  getLicenseInfo,
  clearLicenseCache,
  getProFeatureError,
  ProFeature,
} from '../license/license.js';

describe('validateLicense', () => {
  beforeEach(() => {
    clearLicenseCache();
  });

  it('returns invalid for null key', () => {
    const result = validateLicense(null);
    expect(result.valid).toBe(false);
    expect(result.payload).toBeNull();
    expect(result.error).toContain('No license key');
  });

  it('returns invalid for undefined key', () => {
    const result = validateLicense(undefined);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('No license key');
  });

  it('returns invalid for empty string', () => {
    const result = validateLicense('');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('No license key');
  });

  it('rejects key without HTTPS- prefix', () => {
    const result = validateLicense('INVALID-key.sig');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('must start with "HTTPS-"');
  });

  it('rejects key without dot separator', () => {
    const result = validateLicense('HTTPS-onlyonepart');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Expected format');
  });

  it('rejects key with more than one dot', () => {
    const result = validateLicense('HTTPS-part1.part2.part3');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Expected format');
  });

  it('rejects key with invalid base64 payload', () => {
    const result = validateLicense('HTTPS-!!!invalid!!!.c2ln');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('unable to decode');
  });

  it('rejects key with valid base64 but non-JSON payload', () => {
    const payload = Buffer.from('not json').toString('base64');
    const result = validateLicense(`HTTPS-${payload}.c2ln`);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('unable to decode');
  });

  it('rejects key with missing id in payload', () => {
    const payload = Buffer.from(JSON.stringify({ features: ['mtls'] })).toString('base64');
    const result = validateLicense(`HTTPS-${payload}.c2ln`);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('malformed payload');
  });

  it('rejects key with missing features in payload', () => {
    const payload = Buffer.from(JSON.stringify({ id: 'test-id' })).toString('base64');
    const result = validateLicense(`HTTPS-${payload}.c2ln`);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('malformed payload');
  });

  it('rejects key with non-array features', () => {
    const payload = Buffer.from(JSON.stringify({ id: 'test', features: 'mtls' })).toString('base64');
    const result = validateLicense(`HTTPS-${payload}.c2ln`);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('malformed payload');
  });

  it('rejects key with invalid signature', () => {
    const payload = Buffer.from(
      JSON.stringify({ id: 'test', customer: 'Test', email: 'test@test.com', features: ['mtls'], issued: '2025-01-01', expires: null })
    ).toString('base64');
    const fakeSig = Buffer.from('invalidsignature').toString('base64');
    const result = validateLicense(`HTTPS-${payload}.${fakeSig}`);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('signature verification failed');
  });

  it('returns cached result on second call with same key', () => {
    const result1 = validateLicense(null);
    const result2 = validateLicense(null);
    expect(result1).toEqual(result2);
  });

  it('returns fresh result after clearLicenseCache', () => {
    validateLicense(null);
    clearLicenseCache();
    const result = validateLicense(null);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('No license key');
  });

  it('re-evaluates with different key after cache clear', () => {
    validateLicense(null);
    clearLicenseCache();
    const result = validateLicense('HTTPS-bad.sig');
    expect(result.error).toContain('unable to decode');
  });
});

describe('isProFeatureEnabled', () => {
  beforeEach(() => {
    clearLicenseCache();
  });

  it('returns false for null key', () => {
    expect(isProFeatureEnabled(ProFeature.MTLS, null)).toBe(false);
  });

  it('returns false for undefined key', () => {
    expect(isProFeatureEnabled(ProFeature.FIPS, undefined)).toBe(false);
  });

  it('returns false for invalid key', () => {
    expect(isProFeatureEnabled(ProFeature.PINNING, 'invalid')).toBe(false);
  });
});

describe('hasProLicense', () => {
  beforeEach(() => {
    clearLicenseCache();
  });

  it('returns false for null key', () => {
    expect(hasProLicense(null)).toBe(false);
  });

  it('returns false for invalid key', () => {
    expect(hasProLicense('HTTPS-bad.sig')).toBe(false);
  });
});

describe('getLicenseInfo', () => {
  beforeEach(() => {
    clearLicenseCache();
  });

  it('returns no license info for null key', () => {
    const info = getLicenseInfo(null);
    expect(info.hasLicense).toBe(false);
    expect(info.customer).toBeNull();
    expect(info.features).toEqual([]);
    expect(info.expires).toBeNull();
    expect(info.error).toContain('No license key');
  });

  it('returns error info for invalid key', () => {
    const info = getLicenseInfo('HTTPS-bad.sig');
    expect(info.hasLicense).toBe(false);
    expect(info.error).toBeTruthy();
  });
});

describe('getProFeatureError', () => {
  it('returns message containing feature name for MTLS', () => {
    const msg = getProFeatureError(ProFeature.MTLS);
    expect(msg).toContain('Mutual TLS');
    expect(msg).toContain('Pro license');
  });

  it('returns message containing feature name for FIPS', () => {
    const msg = getProFeatureError(ProFeature.FIPS);
    expect(msg).toContain('FIPS 140-3');
  });

  it('returns message containing feature name for PINNING', () => {
    const msg = getProFeatureError(ProFeature.PINNING);
    expect(msg).toContain('Certificate Pinning');
  });

  it('returns message containing feature name for OCSP', () => {
    const msg = getProFeatureError(ProFeature.OCSP);
    expect(msg).toContain('OCSP');
  });

  it('returns message containing feature name for CRL', () => {
    const msg = getProFeatureError(ProFeature.CRL);
    expect(msg).toContain('CRL');
  });

  it('returns message containing feature name for SIEM', () => {
    const msg = getProFeatureError(ProFeature.SIEM);
    expect(msg).toContain('SIEM');
  });

  it('includes purchase URL', () => {
    const msg = getProFeatureError(ProFeature.MTLS);
    expect(msg).toContain('cyphers.ai');
  });
});
