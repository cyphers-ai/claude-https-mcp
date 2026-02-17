/**
 * Configuration types for the Claude HTTPS MCP tool
 */

export type TlsVersion = 'TLSv1.2' | 'TLSv1.3';

export type CipherProfile = 'modern' | 'intermediate' | 'compatible' | 'fips' | 'custom';

export type CaMode = 'bundled' | 'osPlusBundled' | 'osOnly' | 'custom';

export type PinningMode = 'leaf' | 'intermediate' | 'root' | 'spki';

export type RevocationPolicy = 'ocspWithCrlFallback' | 'ocspOnly' | 'crlOnly' | 'bothRequired';

export type FailMode = 'soft' | 'hard';

export type ProxyAuthType = 'none' | 'basic' | 'digest' | 'ntlm';

/**
 * TLS configuration options
 */
export interface TlsConfig {
  minVersion: TlsVersion;
  maxVersion: TlsVersion;
  cipherProfile: CipherProfile;
  customCiphers: string | null;
  rejectUnauthorized: boolean;
}

/**
 * CA certificate configuration
 */
export interface CaConfig {
  mode: CaMode;
  customBundlePaths: string[];
  additionalCaPaths: string[];
}

/**
 * Client certificate (mTLS) configuration - Pro feature
 */
export interface ClientCertConfig {
  enabled: boolean;
  certPath: string | null;
  keyPath: string | null;
  passphrase: string | null;
  p12Path: string | null;
  p12Passphrase: string | null;
}

/**
 * Certificate pinning configuration - Pro feature
 */
export interface PinningConfig {
  enabled: boolean;
  mode: PinningMode;
  pins: string[];
}

/**
 * Revocation checking configuration - Pro feature
 */
export interface RevocationConfig {
  enabled: boolean;
  policy: RevocationPolicy;
  failMode: FailMode;
  customOcspUrl: string | null;
  customCrlUrl: string | null;
  enableStapling: boolean;
  cacheTtlSeconds: number;
}

/**
 * Proxy configuration
 */
export interface ProxyConfig {
  enabled: boolean;
  url: string | null;
  auth: {
    type: ProxyAuthType;
    username: string | null;
    password: string | null;
    ntlmDomain: string | null;
  };
  bypassList: string[];
}

/**
 * Default request settings
 */
export interface DefaultsConfig {
  timeoutMs: number;
  followRedirects: boolean;
  maxRedirects: number;
  maxBodySizeBytes: number;
}

/**
 * License configuration
 */
export interface LicenseConfig {
  key: string | null;
}

/**
 * Complete configuration schema
 */
export interface HttpsConfig {
  tls: TlsConfig;
  ca: CaConfig;
  clientCert: ClientCertConfig;
  pinning: PinningConfig;
  revocation: RevocationConfig;
  proxy: ProxyConfig;
  defaults: DefaultsConfig;
  license: LicenseConfig;
}

/**
 * Internal request options (resolved from config)
 */
export interface HttpsRequestOptions {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';
  url: string;
  headers?: Record<string, string>;
  body?: string;
  timeout?: number;
}

/**
 * Response from HTTPS request
 */
export interface HttpsResponse {
  statusCode: number;
  statusMessage: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  httpVersion?: string;
}
