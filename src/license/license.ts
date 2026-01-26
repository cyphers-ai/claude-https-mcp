/**
 * License Validation Module
 *
 * Implements offline license validation using Ed25519 signatures.
 * License keys are validated locally without any network calls.
 *
 * License Format: HTTPS-<base64-payload>.<base64-signature>
 */

import * as crypto from 'crypto';

/**
 * Pro features that require a license
 */
export enum ProFeature {
  MTLS = 'mtls',
  PINNING = 'pinning',
  OCSP = 'ocsp',
  CRL = 'crl',
  FIPS = 'fips',
  SIEM = 'siem',
}

/**
 * License payload structure
 */
export interface LicensePayload {
  id: string;
  customer: string;
  email: string;
  features: string[];
  issued: string;
  expires: string | null;
}

/**
 * License validation result
 */
export interface LicenseValidationResult {
  valid: boolean;
  payload: LicensePayload | null;
  error: string | null;
}

/**
 * Ed25519 public key for license verification
 */
const LICENSE_PUBLIC_KEY = 'tp97clI14ctg8Tb6M4H8S5EJ30Ko9MIsDL2VijxeQ3U=';

/**
 * License key prefix
 */
const LICENSE_PREFIX = 'HTTPS-';

// Cached license validation result
let cachedLicense: LicenseValidationResult | null = null;
let cachedLicenseKey: string | null = null;

/**
 * Validate a license key and return the result
 */
export function validateLicense(licenseKey?: string | null): LicenseValidationResult {
  const key = licenseKey || null;

  // Check cache
  if (cachedLicense && cachedLicenseKey === key) {
    // Re-check expiration
    if (cachedLicense.valid && cachedLicense.payload?.expires) {
      const expiresDate = new Date(cachedLicense.payload.expires);
      if (expiresDate < new Date()) {
        cachedLicense = {
          valid: false,
          payload: cachedLicense.payload,
          error: 'License has expired',
        };
      }
    }
    return cachedLicense;
  }

  // No license key provided
  if (!key) {
    const result: LicenseValidationResult = {
      valid: false,
      payload: null,
      error: 'No license key provided. Pro features require a valid license.',
    };
    cachedLicense = result;
    cachedLicenseKey = key;
    return result;
  }

  // Validate format
  if (!key.startsWith(LICENSE_PREFIX)) {
    const result: LicenseValidationResult = {
      valid: false,
      payload: null,
      error: 'Invalid license key format. License must start with "HTTPS-".',
    };
    cachedLicense = result;
    cachedLicenseKey = key;
    return result;
  }

  // Parse license key
  const keyContent = key.slice(LICENSE_PREFIX.length);
  const parts = keyContent.split('.');

  if (parts.length !== 2) {
    const result: LicenseValidationResult = {
      valid: false,
      payload: null,
      error: 'Invalid license key format. Expected format: HTTPS-<payload>.<signature>',
    };
    cachedLicense = result;
    cachedLicenseKey = key;
    return result;
  }

  const [payloadBase64, signatureBase64] = parts;

  // Decode and parse payload
  let payload: LicensePayload;
  try {
    const payloadJson = Buffer.from(payloadBase64, 'base64').toString('utf8');
    payload = JSON.parse(payloadJson) as LicensePayload;
  } catch {
    const result: LicenseValidationResult = {
      valid: false,
      payload: null,
      error: 'Invalid license key: unable to decode payload.',
    };
    cachedLicense = result;
    cachedLicenseKey = key;
    return result;
  }

  // Validate payload structure
  if (!payload.id || !payload.features || !Array.isArray(payload.features)) {
    const result: LicenseValidationResult = {
      valid: false,
      payload: null,
      error: 'Invalid license key: malformed payload.',
    };
    cachedLicense = result;
    cachedLicenseKey = key;
    return result;
  }

  // Verify signature
  try {
    const isValid = verifySignature(payloadBase64, signatureBase64);
    if (!isValid) {
      const result: LicenseValidationResult = {
        valid: false,
        payload,
        error: 'Invalid license key: signature verification failed.',
      };
      cachedLicense = result;
      cachedLicenseKey = key;
      return result;
    }
  } catch (error) {
    const result: LicenseValidationResult = {
      valid: false,
      payload,
      error: `License verification error: ${error instanceof Error ? error.message : String(error)}`,
    };
    cachedLicense = result;
    cachedLicenseKey = key;
    return result;
  }

  // Check expiration
  if (payload.expires) {
    const expiresDate = new Date(payload.expires);
    if (expiresDate < new Date()) {
      const result: LicenseValidationResult = {
        valid: false,
        payload,
        error: `License expired on ${payload.expires}.`,
      };
      cachedLicense = result;
      cachedLicenseKey = key;
      return result;
    }
  }

  // License is valid
  const result: LicenseValidationResult = {
    valid: true,
    payload,
    error: null,
  };
  cachedLicense = result;
  cachedLicenseKey = key;
  return result;
}

/**
 * Verify the Ed25519 signature of a license payload
 */
function verifySignature(payloadBase64: string, signatureBase64: string): boolean {
  try {
    const publicKeyBuffer = Buffer.from(LICENSE_PUBLIC_KEY, 'base64');
    const signatureBuffer = Buffer.from(signatureBase64, 'base64');
    const dataBuffer = Buffer.from(payloadBase64, 'utf8');

    // Create public key object
    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([
        // Ed25519 public key ASN.1 prefix
        Buffer.from('302a300506032b6570032100', 'hex'),
        publicKeyBuffer,
      ]),
      format: 'der',
      type: 'spki',
    });

    // Verify signature
    return crypto.verify(null, dataBuffer, publicKey, signatureBuffer);
  } catch {
    return false;
  }
}

/**
 * Check if a specific Pro feature is enabled
 */
export function isProFeatureEnabled(feature: ProFeature, licenseKey?: string | null): boolean {
  const license = validateLicense(licenseKey);
  if (!license.valid || !license.payload) {
    return false;
  }
  return license.payload.features.includes(feature);
}

/**
 * Check if any Pro license is active
 */
export function hasProLicense(licenseKey?: string | null): boolean {
  const license = validateLicense(licenseKey);
  return license.valid;
}

/**
 * Get the current license information
 */
export function getLicenseInfo(licenseKey?: string | null): {
  hasLicense: boolean;
  customer: string | null;
  features: string[];
  expires: string | null;
  error: string | null;
} {
  const license = validateLicense(licenseKey);
  return {
    hasLicense: license.valid,
    customer: license.payload?.customer || null,
    features: license.payload?.features || [],
    expires: license.payload?.expires || null,
    error: license.error,
  };
}

/**
 * Clear the cached license
 */
export function clearLicenseCache(): void {
  cachedLicense = null;
  cachedLicenseKey = null;
}

/**
 * Get error message for unlicensed Pro feature usage
 */
export function getProFeatureError(feature: ProFeature): string {
  const featureNames: Record<ProFeature, string> = {
    [ProFeature.MTLS]: 'Mutual TLS (mTLS) / Client Certificates',
    [ProFeature.PINNING]: 'Certificate Pinning',
    [ProFeature.OCSP]: 'Advanced OCSP Revocation Checking',
    [ProFeature.CRL]: 'Advanced CRL Revocation Checking',
    [ProFeature.FIPS]: 'FIPS 140-3 Mode',
    [ProFeature.SIEM]: 'SIEM Log Export',
  };

  const featureName = featureNames[feature] || feature;

  return (
    `${featureName} requires a Pro license.\n\n` +
    'Purchase a license at https://cyphers.ai or contact sales@cyphers.ai\n\n' +
    'To activate: Add your license key to the "license.key" field in ~/.claude/https-config.json'
  );
}
