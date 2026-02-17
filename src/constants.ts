/**
 * Constants for the Claude HTTPS MCP tool
 * Includes cipher profiles, TLS versions, and error codes
 */

import type { CipherProfile, TlsVersion } from './config/types.js';

/**
 * Cipher suite profiles following Mozilla SSL Configuration Generator recommendations
 * https://ssl-config.mozilla.org/
 */
export const CIPHER_PROFILES: Record<CipherProfile, string> = {
  // Modern: TLS 1.3 only, strongest security
  modern: [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
  ].join(':'),

  // Intermediate: TLS 1.2+, balanced security and compatibility (recommended)
  intermediate: [
    // TLS 1.3 ciphers
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
    // TLS 1.2 ciphers
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'DHE-RSA-AES256-GCM-SHA384',
    'DHE-RSA-AES128-GCM-SHA256',
  ].join(':'),

  // Compatible: Wider support, still no legacy insecure ciphers
  compatible: [
    // TLS 1.3 ciphers
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
    // TLS 1.2 ECDHE ciphers
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-SHA384',
    'ECDHE-RSA-AES256-SHA384',
    'ECDHE-ECDSA-AES128-SHA256',
    'ECDHE-RSA-AES128-SHA256',
    // TLS 1.2 DHE ciphers
    'DHE-RSA-AES256-GCM-SHA384',
    'DHE-RSA-AES128-GCM-SHA256',
    'DHE-RSA-AES256-SHA256',
    'DHE-RSA-AES128-SHA256',
  ].join(':'),

  // FIPS: Only FIPS 140-3 approved algorithms (Pro feature)
  fips: [
    // TLS 1.3 FIPS-approved
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_GCM_SHA256',
    // TLS 1.2 FIPS-approved
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'DHE-RSA-AES256-GCM-SHA384',
    'DHE-RSA-AES128-GCM-SHA256',
  ].join(':'),

  // Custom: Empty, user provides their own
  custom: '',
};

/**
 * Default connection pool settings
 */
export const DEFAULT_CONNECTION_POOL_SIZE = 6;
export const DEFAULT_IDLE_TIMEOUT = 30000; // 30 seconds
export const DEFAULT_TIMEOUT = 30000; // 30 seconds

/**
 * TLS version configuration
 */
export const TLS_VERSIONS: Record<TlsVersion, string> = {
  'TLSv1.2': 'TLSv1.2',
  'TLSv1.3': 'TLSv1.3',
};

/**
 * Error codes
 */
export const ERROR_CODES = {
  // TLS errors
  EHTTPS_TLS_HANDSHAKE: 'EHTTPS_TLS_HANDSHAKE',
  EHTTPS_CERT_VERIFY: 'EHTTPS_CERT_VERIFY',
  EHTTPS_CERT_EXPIRED: 'EHTTPS_CERT_EXPIRED',
  EHTTPS_CERT_NOT_YET_VALID: 'EHTTPS_CERT_NOT_YET_VALID',
  EHTTPS_HOSTNAME_MISMATCH: 'EHTTPS_HOSTNAME_MISMATCH',

  // Pinning errors
  EHTTPS_PIN_MISMATCH: 'EHTTPS_PIN_MISMATCH',

  // Revocation errors
  EHTTPS_CERT_REVOKED: 'EHTTPS_CERT_REVOKED',
  EHTTPS_OCSP_FAILED: 'EHTTPS_OCSP_FAILED',
  EHTTPS_CRL_FAILED: 'EHTTPS_CRL_FAILED',
  EHTTPS_REVOCATION_CHECK_FAILED: 'EHTTPS_REVOCATION_CHECK_FAILED',

  // Connection errors
  EHTTPS_TIMEOUT: 'EHTTPS_TIMEOUT',
  EHTTPS_CONNECTION_REFUSED: 'EHTTPS_CONNECTION_REFUSED',
  EHTTPS_DNS_RESOLVE: 'EHTTPS_DNS_RESOLVE',

  // Proxy errors
  EHTTPS_PROXY_AUTH: 'EHTTPS_PROXY_AUTH',
  EHTTPS_PROXY_CONNECT: 'EHTTPS_PROXY_CONNECT',

  // FIPS errors
  EHTTPS_FIPS_NOT_AVAILABLE: 'EHTTPS_FIPS_NOT_AVAILABLE',
  EHTTPS_FIPS_CIPHER_REJECTED: 'EHTTPS_FIPS_CIPHER_REJECTED',

  // License errors
  EHTTPS_LICENSE_REQUIRED: 'EHTTPS_LICENSE_REQUIRED',
  EHTTPS_LICENSE_INVALID: 'EHTTPS_LICENSE_INVALID',
  EHTTPS_LICENSE_EXPIRED: 'EHTTPS_LICENSE_EXPIRED',

  // CA errors
  EHTTPS_CA_LOAD_FAILED: 'EHTTPS_CA_LOAD_FAILED',
  EHTTPS_CA_INVALID: 'EHTTPS_CA_INVALID',

  // Config errors
  EHTTPS_CONFIG_NOT_FOUND: 'EHTTPS_CONFIG_NOT_FOUND',
  EHTTPS_CONFIG_INVALID: 'EHTTPS_CONFIG_INVALID',

  // Request errors
  EHTTPS_BODY_TOO_LARGE: 'EHTTPS_BODY_TOO_LARGE',
} as const;

export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];
