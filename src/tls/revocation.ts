/**
 * Certificate Revocation Checking Module
 *
 * Implements OCSP (Online Certificate Status Protocol) and CRL (Certificate Revocation List)
 * checking for certificate validation. This is a Pro feature.
 */

import * as crypto from 'crypto';
import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import type { RevocationConfig } from '../config/types.js';

/**
 * OCSP Response Status
 */
export enum OcspStatus {
  GOOD = 'good',
  REVOKED = 'revoked',
  UNKNOWN = 'unknown',
}

/**
 * CRL Check Result
 */
export interface CrlCheckResult {
  revoked: boolean;
  reason?: string;
  revocationDate?: Date;
}

/**
 * Revocation Check Result
 */
export interface RevocationCheckResult {
  checked: boolean;
  revoked: boolean;
  method: 'ocsp' | 'ocsp-stapling' | 'crl' | 'none';
  status: OcspStatus | 'crl-revoked' | 'crl-valid' | 'error' | 'skipped';
  error?: string;
  ocspUrl?: string;
  crlUrl?: string;
  cached?: boolean;
}

/**
 * Cache entry for revocation results
 */
interface RevocationCacheEntry {
  result: RevocationCheckResult;
  expiresAt: number;
}

/**
 * Revocation cache
 */
const revocationCache = new Map<string, RevocationCacheEntry>();

const DEFAULT_CACHE_TTL = 300;
const MAX_CACHE_TTL = 86400;

/**
 * Get cached revocation result
 */
function getCachedResult(key: string): RevocationCheckResult | null {
  const entry = revocationCache.get(key);
  if (!entry) return null;

  if (Date.now() > entry.expiresAt) {
    revocationCache.delete(key);
    return null;
  }

  return { ...entry.result, cached: true };
}

/**
 * Cache a revocation result
 */
function cacheResult(key: string, result: RevocationCheckResult, ttlSeconds: number): void {
  if (ttlSeconds <= 0) return;

  const effectiveTtl = Math.min(ttlSeconds, MAX_CACHE_TTL);
  revocationCache.set(key, {
    result,
    expiresAt: Date.now() + effectiveTtl * 1000,
  });
}

/**
 * Clear the revocation cache
 */
export function clearRevocationCache(): void {
  revocationCache.clear();
}

/**
 * Extract OCSP responder URL from certificate
 */
export function extractOcspUrl(cert: crypto.X509Certificate): string | undefined {
  try {
    const infoAccess = cert.infoAccess;
    if (!infoAccess) return undefined;

    const lines = infoAccess.split('\n');
    for (const line of lines) {
      if (line.startsWith('OCSP - URI:')) {
        return line.substring('OCSP - URI:'.length).trim();
      }
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * Extract CRL distribution points from certificate
 */
export function extractCrlUrls(cert: crypto.X509Certificate): string[] {
  try {
    const urls: string[] = [];
    const certPem = cert.toString();
    const crlRegex = /URI:(https?:\/\/[^\s,\n]+\.crl)/gi;
    let match;
    while ((match = crlRegex.exec(certPem)) !== null) {
      urls.push(match[1]);
    }
    return urls;
  } catch {
    return [];
  }
}

/**
 * Build OCSP request for a certificate
 */
function buildOcspRequest(cert: crypto.X509Certificate, issuerCert: crypto.X509Certificate): Buffer {
  const serialHex = cert.serialNumber;
  const serialBytes = Buffer.from(serialHex, 'hex');

  const issuerNameHash = crypto
    .createHash('sha1')
    .update(Buffer.from(issuerCert.subject, 'utf8'))
    .digest();

  const issuerKeyHash = crypto
    .createHash('sha1')
    .update(issuerCert.publicKey.export({ type: 'spki', format: 'der' }))
    .digest();

  const sha1AlgoId = Buffer.from([0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00]);

  const certIdContent = Buffer.concat([
    sha1AlgoId,
    Buffer.from([0x04, issuerNameHash.length]),
    issuerNameHash,
    Buffer.from([0x04, issuerKeyHash.length]),
    issuerKeyHash,
    Buffer.from([0x02, serialBytes.length]),
    serialBytes,
  ]);

  const certId = Buffer.concat([Buffer.from([0x30, certIdContent.length]), certIdContent]);

  const request = Buffer.concat([Buffer.from([0x30, certId.length]), certId]);

  const requestList = Buffer.concat([Buffer.from([0x30, request.length]), request]);

  const tbsRequest = Buffer.concat([Buffer.from([0x30, requestList.length]), requestList]);

  const ocspRequest = Buffer.concat([Buffer.from([0x30, tbsRequest.length]), tbsRequest]);

  return ocspRequest;
}

/**
 * Parse OCSP response and extract status
 */
function parseOcspResponse(response: Buffer): OcspStatus {
  try {
    if (response.length < 10) {
      return OcspStatus.UNKNOWN;
    }

    for (let i = 0; i < response.length - 1; i++) {
      if (response[i] === 0x80 && response[i + 1] === 0x00) {
        return OcspStatus.GOOD;
      }
      if (response[i] === 0xa1) {
        return OcspStatus.REVOKED;
      }
      if (response[i] === 0x82 && response[i + 1] === 0x00) {
        return OcspStatus.UNKNOWN;
      }
    }

    return OcspStatus.UNKNOWN;
  } catch {
    return OcspStatus.UNKNOWN;
  }
}

/**
 * Send OCSP request to responder
 */
async function sendOcspRequest(
  ocspUrl: string,
  requestData: Buffer,
  timeout: number = 10000
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const url = new URL(ocspUrl);
    const isHttps = url.protocol === 'https:';

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/ocsp-request',
        'Content-Length': requestData.length,
      },
      timeout,
    };

    const request = isHttps ? https.request : http.request;
    const req = request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        if (res.statusCode === 200) {
          resolve(Buffer.concat(chunks));
        } else {
          reject(new Error(`OCSP responder returned status ${res.statusCode}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('OCSP request timed out'));
    });

    req.write(requestData);
    req.end();
  });
}

/**
 * Check OCSP stapled response
 */
export function checkOcspStapling(stapledResponse: Buffer | undefined): RevocationCheckResult {
  if (!stapledResponse || stapledResponse.length === 0) {
    return {
      checked: false,
      revoked: false,
      method: 'ocsp-stapling',
      status: 'skipped',
      error: 'No OCSP stapled response available',
    };
  }

  try {
    const status = parseOcspResponse(stapledResponse);

    return {
      checked: true,
      revoked: status === OcspStatus.REVOKED,
      method: 'ocsp-stapling',
      status,
    };
  } catch (error) {
    return {
      checked: false,
      revoked: false,
      method: 'ocsp-stapling',
      status: 'error',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Check certificate revocation via OCSP
 */
export async function checkOcsp(
  cert: crypto.X509Certificate,
  issuerCert: crypto.X509Certificate,
  customOcspUrl?: string | null,
  timeout: number = 10000,
  cacheTtl: number = DEFAULT_CACHE_TTL
): Promise<RevocationCheckResult> {
  const cacheKey = `ocsp:${cert.serialNumber}`;

  if (cacheTtl > 0) {
    const cached = getCachedResult(cacheKey);
    if (cached) {
      return cached;
    }
  }

  try {
    const ocspUrl = customOcspUrl || extractOcspUrl(cert);
    if (!ocspUrl) {
      return {
        checked: false,
        revoked: false,
        method: 'ocsp',
        status: 'skipped',
        error: 'No OCSP responder URL found in certificate',
      };
    }

    const ocspRequest = buildOcspRequest(cert, issuerCert);
    const ocspResponse = await sendOcspRequest(ocspUrl, ocspRequest, timeout);
    const status = parseOcspResponse(ocspResponse);

    const result: RevocationCheckResult = {
      checked: true,
      revoked: status === OcspStatus.REVOKED,
      method: 'ocsp',
      status,
      ocspUrl,
    };

    cacheResult(cacheKey, result, cacheTtl);

    return result;
  } catch (error) {
    return {
      checked: false,
      revoked: false,
      method: 'ocsp',
      status: 'error',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Download CRL
 */
async function downloadCrl(crlUrl: string, timeout: number = 10000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const url = new URL(crlUrl);
    const isHttps = url.protocol === 'https:';

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method: 'GET',
      timeout,
    };

    const request = isHttps ? https.request : http.request;
    const req = request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        if (res.statusCode === 200) {
          resolve(Buffer.concat(chunks));
        } else {
          reject(new Error(`CRL download failed with status ${res.statusCode}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('CRL download timed out'));
    });

    req.end();
  });
}

/**
 * Check if serial number is in CRL
 */
function isSerialInCrl(crlData: Buffer, serialNumber: string): CrlCheckResult {
  try {
    const serialBytes = Buffer.from(serialNumber, 'hex');

    for (let i = 0; i < crlData.length - serialBytes.length - 2; i++) {
      if (crlData[i] === 0x02) {
        const len = crlData[i + 1];
        if (len === serialBytes.length) {
          const potentialSerial = crlData.subarray(i + 2, i + 2 + len);
          if (potentialSerial.equals(serialBytes)) {
            return {
              revoked: true,
              reason: 'Certificate serial number found in CRL',
            };
          }
        }
      }
    }

    return { revoked: false };
  } catch {
    return { revoked: false };
  }
}

/**
 * Check certificate revocation via CRL
 */
export async function checkCrl(
  cert: crypto.X509Certificate,
  customCrlUrl?: string | null,
  timeout: number = 10000,
  cacheTtl: number = DEFAULT_CACHE_TTL
): Promise<RevocationCheckResult> {
  const cacheKey = `crl:${cert.serialNumber}`;

  if (cacheTtl > 0) {
    const cached = getCachedResult(cacheKey);
    if (cached) {
      return cached;
    }
  }

  try {
    const crlUrls = customCrlUrl ? [customCrlUrl] : extractCrlUrls(cert);
    if (crlUrls.length === 0) {
      return {
        checked: false,
        revoked: false,
        method: 'crl',
        status: 'skipped',
        error: 'No CRL distribution points found in certificate',
      };
    }

    for (const crlUrl of crlUrls) {
      try {
        const crlData = await downloadCrl(crlUrl, timeout);
        const crlResult = isSerialInCrl(crlData, cert.serialNumber);

        const result: RevocationCheckResult = crlResult.revoked
          ? {
              checked: true,
              revoked: true,
              method: 'crl',
              status: 'crl-revoked',
              crlUrl,
            }
          : {
              checked: true,
              revoked: false,
              method: 'crl',
              status: 'crl-valid',
              crlUrl,
            };

        cacheResult(cacheKey, result, cacheTtl);

        return result;
      } catch {
        continue;
      }
    }

    return {
      checked: false,
      revoked: false,
      method: 'crl',
      status: 'error',
      error: 'Failed to download or parse any CRL',
    };
  } catch (error) {
    return {
      checked: false,
      revoked: false,
      method: 'crl',
      status: 'error',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Check certificate revocation based on policy
 */
export async function checkRevocation(
  cert: crypto.X509Certificate,
  issuerCert: crypto.X509Certificate | null,
  options: RevocationConfig,
  timeout: number = 10000,
  stapledResponse?: Buffer
): Promise<RevocationCheckResult> {
  const { policy, failMode, customOcspUrl, customCrlUrl, enableStapling, cacheTtlSeconds } = options;
  const effectiveCacheTtl = cacheTtlSeconds ?? DEFAULT_CACHE_TTL;

  let ocspResult: RevocationCheckResult | null = null;
  let crlResult: RevocationCheckResult | null = null;

  const doOcsp = policy === 'ocspOnly' || policy === 'ocspWithCrlFallback' || policy === 'bothRequired';
  const doCrl = policy === 'crlOnly' || policy === 'ocspWithCrlFallback' || policy === 'bothRequired';

  // Try OCSP stapling first if enabled
  if (enableStapling && stapledResponse && stapledResponse.length > 0) {
    const staplingResult = checkOcspStapling(stapledResponse);
    if (staplingResult.checked) {
      if (staplingResult.revoked) {
        return staplingResult;
      }
      if (staplingResult.status === OcspStatus.GOOD) {
        return staplingResult;
      }
    }
  }

  // OCSP check
  if (doOcsp && issuerCert) {
    ocspResult = await checkOcsp(cert, issuerCert, customOcspUrl, timeout, effectiveCacheTtl);

    if (ocspResult.revoked) {
      return ocspResult;
    }

    if (policy === 'ocspOnly') {
      if (!ocspResult.checked && failMode === 'hard') {
        throw new Error(`OCSP check failed (hard-fail mode): ${ocspResult.error}`);
      }
      return ocspResult;
    }
  }

  // CRL check
  if (doCrl) {
    if (policy === 'ocspWithCrlFallback' && ocspResult?.checked) {
      return ocspResult;
    }

    crlResult = await checkCrl(cert, customCrlUrl, timeout, effectiveCacheTtl);

    if (crlResult.revoked) {
      return crlResult;
    }

    if (policy === 'crlOnly') {
      if (!crlResult.checked && failMode === 'hard') {
        throw new Error(`CRL check failed (hard-fail mode): ${crlResult.error}`);
      }
      return crlResult;
    }
  }

  // For bothRequired policy
  if (policy === 'bothRequired') {
    const bothChecked = (ocspResult?.checked ?? false) && (crlResult?.checked ?? false);

    if (!bothChecked && failMode === 'hard') {
      const errors = [];
      if (!ocspResult?.checked) errors.push(`OCSP: ${ocspResult?.error || 'not checked'}`);
      if (!crlResult?.checked) errors.push(`CRL: ${crlResult?.error || 'not checked'}`);
      throw new Error(`Revocation check failed (hard-fail mode): ${errors.join('; ')}`);
    }

    return {
      checked: bothChecked,
      revoked: false,
      method: 'ocsp',
      status: bothChecked ? OcspStatus.GOOD : 'error',
      error: bothChecked ? undefined : 'Not all revocation checks completed',
    };
  }

  // For ocspWithCrlFallback
  if (policy === 'ocspWithCrlFallback') {
    if (ocspResult?.checked) return ocspResult;
    if (crlResult?.checked) return crlResult;

    if (failMode === 'hard') {
      throw new Error(`Revocation check failed (hard-fail mode): Neither OCSP nor CRL check succeeded`);
    }

    return {
      checked: false,
      revoked: false,
      method: 'none',
      status: 'error',
      error: 'Neither OCSP nor CRL check succeeded',
    };
  }

  return (
    ocspResult ||
    crlResult || {
      checked: false,
      revoked: false,
      method: 'none',
      status: 'skipped',
    }
  );
}
