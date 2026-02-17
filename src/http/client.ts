/**
 * HTTPS Client
 *
 * Simplified HTTPS client that makes requests with TLS configuration
 * loaded from the config file.
 */

import * as crypto from 'crypto';
import * as https from 'https';
import * as http from 'http';
import * as tls from 'tls';
import { URL } from 'url';
import type { HttpsConfig, HttpsRequestOptions, HttpsResponse } from '../config/types.js';
import { getCaCertificates } from '../tls/ca-utils.js';
import { CIPHER_PROFILES, ERROR_CODES, DEFAULT_TIMEOUT } from '../constants.js';
import {
  createPinningCheckFunction,
  getTlsErrorMessage,
  validateTlsVersions,
  loadCertificateFromFile,
  loadPrivateKeyFromFile,
  parsePkcs12,
} from '../tls/tls-utils.js';
import { checkRevocation } from '../tls/revocation.js';
import { isProFeatureEnabled, ProFeature, getProFeatureError } from '../license/license.js';

/**
 * Make an HTTPS request with the given configuration
 */
export async function makeRequest(
  options: HttpsRequestOptions,
  config: HttpsConfig
): Promise<HttpsResponse> {
  const parsedUrl = new URL(options.url);

  // Only support HTTPS
  if (parsedUrl.protocol !== 'https:') {
    throw new Error('Only HTTPS URLs are supported');
  }

  // Check if we should bypass proxy for this host
  let useProxy = config.proxy.enabled && config.proxy.url;
  if (useProxy && shouldBypassProxy(parsedUrl.hostname, config.proxy.bypassList)) {
    useProxy = false;
  }

  if (useProxy) {
    return makeProxiedRequest(options, parsedUrl, config);
  }

  return makeDirectRequest(options, parsedUrl, config);
}

/**
 * Make a direct HTTPS request (no proxy)
 */
async function makeDirectRequest(
  options: HttpsRequestOptions,
  parsedUrl: URL,
  config: HttpsConfig
): Promise<HttpsResponse> {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || config.defaults.timeoutMs || DEFAULT_TIMEOUT;

    // Build TLS options
    const tlsOptions = buildTlsOptions(config);

    // Build request options
    const requestOptions: https.RequestOptions = {
      method: options.method,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || 443,
      path: parsedUrl.pathname + parsedUrl.search,
      headers: options.headers,
      timeout,
      ...tlsOptions,
    };

    const req = https.request(requestOptions, (res) => {
      const chunks: Buffer[] = [];

      res.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
      });

      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');

        resolve({
          statusCode: res.statusCode || 0,
          statusMessage: res.statusMessage || '',
          headers: res.headers as Record<string, string | string[] | undefined>,
          body,
          httpVersion: `HTTP/${res.httpVersion}`,
        });
      });
    });

    // Handle revocation checking
    req.on('socket', (socket) => {
      const handleSecureConnect = async () => {
        if (config.revocation.enabled && socket instanceof tls.TLSSocket) {
          // Check license for revocation features
          if (
            config.revocation.policy !== 'ocspWithCrlFallback' ||
            config.revocation.failMode === 'hard'
          ) {
            if (!isProFeatureEnabled(ProFeature.OCSP, config.license.key)) {
              // Continue without revocation check if no license
              return;
            }
          }

          try {
            const peerCert = socket.getPeerCertificate(true);
            if (peerCert && Object.keys(peerCert).length > 0 && peerCert.raw) {
              const certPem = `-----BEGIN CERTIFICATE-----\n${peerCert.raw
                .toString('base64')
                .match(/.{1,64}/g)
                ?.join('\n')}\n-----END CERTIFICATE-----`;
              const cert = new crypto.X509Certificate(certPem);

              let issuerCert: crypto.X509Certificate | null = null;
              if (peerCert.issuerCertificate && peerCert.issuerCertificate.raw) {
                const issuerPem = `-----BEGIN CERTIFICATE-----\n${peerCert.issuerCertificate.raw
                  .toString('base64')
                  .match(/.{1,64}/g)
                  ?.join('\n')}\n-----END CERTIFICATE-----`;
                issuerCert = new crypto.X509Certificate(issuerPem);
              }

              const result = await checkRevocation(cert, issuerCert, config.revocation, timeout);

              if (result.revoked) {
                socket.destroy();
                reject(
                  new Error(
                    `${ERROR_CODES.EHTTPS_CERT_REVOKED}: Certificate has been revoked (${result.method.toUpperCase()})`
                  )
                );
                return;
              }

              if (!result.checked && config.revocation.failMode === 'hard') {
                socket.destroy();
                reject(
                  new Error(
                    `${ERROR_CODES.EHTTPS_REVOCATION_CHECK_FAILED}: Revocation check failed (hard-fail mode): ${result.error}`
                  )
                );
                return;
              }
            }
          } catch (error) {
            if (config.revocation.failMode === 'hard') {
              socket.destroy();
              reject(
                new Error(
                  `${ERROR_CODES.EHTTPS_REVOCATION_CHECK_FAILED}: ${
                    error instanceof Error ? error.message : String(error)
                  }`
                )
              );
              return;
            }
          }
        }
      };

      if (socket instanceof tls.TLSSocket) {
        socket.on('secureConnect', () => {
          void handleSecureConnect();
        });
      }
    });

    req.on('error', (error: NodeJS.ErrnoException) => {
      reject(mapError(error));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`${ERROR_CODES.EHTTPS_TIMEOUT}: Request timed out after ${timeout}ms`));
    });

    // Send body if present
    if (options.body) {
      req.write(options.body);
    }

    req.end();
  });
}

/**
 * Make a proxied HTTPS request using CONNECT tunnel
 */
async function makeProxiedRequest(
  options: HttpsRequestOptions,
  targetUrl: URL,
  config: HttpsConfig
): Promise<HttpsResponse> {
  return new Promise((resolve, reject) => {
    if (!config.proxy.url) {
      reject(new Error('Proxy URL is required'));
      return;
    }

    const proxyUrl = new URL(config.proxy.url);
    const timeout = options.timeout || config.defaults.timeoutMs || DEFAULT_TIMEOUT;
    const connectPath = `${targetUrl.hostname}:${targetUrl.port || 443}`;

    // Build proxy CONNECT request
    const connectOptions: http.RequestOptions = {
      method: 'CONNECT',
      hostname: proxyUrl.hostname,
      port: proxyUrl.port || (proxyUrl.protocol === 'https:' ? 443 : 80),
      path: connectPath,
      headers: {
        Host: connectPath,
      },
      timeout,
    };

    // Add proxy authentication header if configured
    if (config.proxy.auth.type !== 'none' && config.proxy.auth.username) {
      const authHeader = buildProxyAuthHeader(config);
      if (authHeader) {
        connectOptions.headers = {
          ...connectOptions.headers,
          'Proxy-Authorization': authHeader,
        };
      }
    }

    const proxyRequest = proxyUrl.protocol === 'https:' ? https.request : http.request;

    const connectReq = proxyRequest(connectOptions);

    connectReq.on('connect', (res, socket) => {
      if (res.statusCode === 407) {
        socket.destroy();
        reject(new Error(`${ERROR_CODES.EHTTPS_PROXY_AUTH}: Proxy authentication failed`));
        return;
      }

      if (res.statusCode !== 200) {
        socket.destroy();
        reject(
          new Error(
            `${ERROR_CODES.EHTTPS_PROXY_CONNECT}: Proxy CONNECT failed with status ${res.statusCode}`
          )
        );
        return;
      }

      // Upgrade the socket to TLS
      const tlsOptions = buildTlsOptions(config);
      const tlsSocket = tls.connect({
        socket,
        servername: targetUrl.hostname,
        ...tlsOptions,
      });

      tlsSocket.on('secureConnect', () => {
        // Send the actual request through the TLS tunnel
        sendRequestThroughTunnel(options, targetUrl, tlsSocket, resolve, reject);
      });

      tlsSocket.on('error', (error) => {
        reject(mapError(error));
      });
    });

    connectReq.on('error', (error) => {
      reject(new Error(`${ERROR_CODES.EHTTPS_PROXY_CONNECT}: ${error.message}`));
    });

    connectReq.on('timeout', () => {
      connectReq.destroy();
      reject(new Error(`${ERROR_CODES.EHTTPS_TIMEOUT}: Proxy connection timed out`));
    });

    connectReq.end();
  });
}

/**
 * Send HTTP request through established TLS tunnel
 */
function sendRequestThroughTunnel(
  options: HttpsRequestOptions,
  targetUrl: URL,
  socket: tls.TLSSocket,
  resolve: (value: HttpsResponse) => void,
  reject: (reason: Error) => void
): void {
  const requestLine = `${options.method} ${targetUrl.pathname}${targetUrl.search} HTTP/1.1\r\n`;
  const headers = [
    `Host: ${targetUrl.host}`,
    ...Object.entries(options.headers || {}).map(([k, v]) => `${k}: ${v}`),
    'Connection: close',
  ];

  if (options.body) {
    headers.push(`Content-Length: ${Buffer.byteLength(options.body)}`);
  }

  const requestData = requestLine + headers.join('\r\n') + '\r\n\r\n' + (options.body || '');

  socket.write(requestData);

  const chunks: Buffer[] = [];

  socket.on('data', (chunk: Buffer) => {
    chunks.push(chunk);
  });

  socket.on('end', () => {
    const response = Buffer.concat(chunks).toString('utf8');
    const parsed = parseRawHttpResponse(response);

    resolve({
      ...parsed,
      httpVersion: 'HTTP/1.1',
    });

    socket.destroy();
  });

  socket.on('error', (error) => {
    reject(mapError(error));
  });
}

/**
 * Build TLS options from configuration
 */
function buildTlsOptions(config: HttpsConfig): tls.ConnectionOptions {
  // Validate TLS version configuration
  validateTlsVersions(config.tls.minVersion, config.tls.maxVersion);

  // Get cipher string from profile or custom
  let ciphers: string;
  if (config.tls.cipherProfile === 'custom' && config.tls.customCiphers) {
    ciphers = config.tls.customCiphers;
  } else if (config.tls.cipherProfile === 'fips') {
    // Check license for FIPS
    if (!isProFeatureEnabled(ProFeature.FIPS, config.license.key)) {
      throw new Error(getProFeatureError(ProFeature.FIPS));
    }
    // Verify OpenSSL FIPS mode is active
    if (crypto.getFips() === 0) {
      throw new Error(
        `${ERROR_CODES.EHTTPS_FIPS_NOT_AVAILABLE}: FIPS cipher profile requires OpenSSL FIPS mode to be enabled. ` +
        'The current Node.js build does not have FIPS mode active. ' +
        'See https://nodejs.org/api/crypto.html#cryptosetfipsenabled for details.'
      );
    }
    ciphers = CIPHER_PROFILES.fips;
  } else {
    ciphers = CIPHER_PROFILES[config.tls.cipherProfile];
  }

  const tlsOptions: tls.ConnectionOptions = {
    minVersion: config.tls.minVersion,
    maxVersion: config.tls.maxVersion,
    ciphers,
    rejectUnauthorized: config.tls.rejectUnauthorized,
  };

  // Load CA certificates
  const ca = getCaCertificates(
    config.ca.mode,
    config.ca.customBundlePaths,
    config.ca.additionalCaPaths
  );
  if (ca && (Array.isArray(ca) ? ca.length > 0 : true)) {
    tlsOptions.ca = ca;
  }

  // Add client certificate if configured (mTLS) - Pro feature
  if (config.clientCert.enabled) {
    if (!isProFeatureEnabled(ProFeature.MTLS, config.license.key)) {
      throw new Error(getProFeatureError(ProFeature.MTLS));
    }

    if (config.clientCert.p12Path) {
      // Load from PKCS#12 file
      const p12Buffer = loadCertificateFromFile(config.clientCert.p12Path);
      const { cert, key } = parsePkcs12(p12Buffer, config.clientCert.p12Passphrase || '');
      tlsOptions.cert = cert;
      tlsOptions.key = key;
    } else if (config.clientCert.certPath && config.clientCert.keyPath) {
      // Load from separate PEM files
      tlsOptions.cert = loadCertificateFromFile(config.clientCert.certPath);
      tlsOptions.key = loadPrivateKeyFromFile(config.clientCert.keyPath);
      if (config.clientCert.passphrase) {
        tlsOptions.passphrase = config.clientCert.passphrase;
      }
    }
  }

  // Add certificate pinning if configured - Pro feature
  if (config.pinning.enabled && config.pinning.pins.length > 0) {
    if (!isProFeatureEnabled(ProFeature.PINNING, config.license.key)) {
      throw new Error(getProFeatureError(ProFeature.PINNING));
    }

    tlsOptions.checkServerIdentity = createPinningCheckFunction(
      config.pinning.pins,
      config.pinning.mode
    );
  }

  return tlsOptions;
}

/**
 * Build proxy authentication header
 * @internal Exported for testing
 */
export function buildProxyAuthHeader(config: HttpsConfig): string | null {
  if (config.proxy.auth.type === 'none' || !config.proxy.auth.username) {
    return null;
  }

  if (config.proxy.auth.type === 'basic') {
    const credentials = Buffer.from(
      `${config.proxy.auth.username}:${config.proxy.auth.password || ''}`
    ).toString('base64');
    return `Basic ${credentials}`;
  }

  // Digest and NTLM require Pro license
  if (config.proxy.auth.type === 'digest' || config.proxy.auth.type === 'ntlm') {
    // For now, only support basic auth in the MCP tool
    // Advanced auth methods require challenge-response which is complex
    throw new Error('Digest and NTLM proxy authentication are not yet supported in this MCP tool');
  }

  return null;
}

/**
 * Check if a host should bypass the proxy
 * @internal Exported for testing
 */
export function shouldBypassProxy(hostname: string, bypassList: string[]): boolean {
  if (!bypassList || bypassList.length === 0) {
    return false;
  }

  for (const pattern of bypassList) {
    if (pattern.startsWith('.')) {
      if (hostname.endsWith(pattern) || hostname === pattern.slice(1)) {
        return true;
      }
    } else if (hostname === pattern || hostname.endsWith(`.${pattern}`)) {
      return true;
    }
  }

  return false;
}

/**
 * Parse raw HTTP response string
 * @internal Exported for testing
 */
export function parseRawHttpResponse(response: string): Omit<HttpsResponse, 'httpVersion'> {
  const headerEndIndex = response.indexOf('\r\n\r\n');
  const headerPart = headerEndIndex > -1 ? response.slice(0, headerEndIndex) : response;
  const body = headerEndIndex > -1 ? response.slice(headerEndIndex + 4) : '';

  const lines = headerPart.split('\r\n');
  const statusLine = lines[0] || '';
  const statusMatch = statusLine.match(/HTTP\/[\d.]+ (\d+) (.*)/);

  const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  const statusMessage = statusMatch ? statusMatch[2] : '';

  const headers: Record<string, string | string[] | undefined> = {};
  for (let i = 1; i < lines.length; i++) {
    const colonIndex = lines[i].indexOf(':');
    if (colonIndex > -1) {
      const key = lines[i].slice(0, colonIndex).trim().toLowerCase();
      const value = lines[i].slice(colonIndex + 1).trim();
      headers[key] = value;
    }
  }

  return {
    statusCode,
    statusMessage,
    headers,
    body,
  };
}

/**
 * Map Node.js errors to HTTPS error codes
 * @internal Exported for testing
 */
export function mapError(error: NodeJS.ErrnoException | Error): Error {
  const message = error.message;
  const code = 'code' in error ? error.code : undefined;

  if (code === 'ECONNREFUSED') {
    return new Error(`${ERROR_CODES.EHTTPS_CONNECTION_REFUSED}: Connection refused - ${message}`);
  }

  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
    return new Error(`${ERROR_CODES.EHTTPS_DNS_RESOLVE}: DNS resolution failed - ${message}`);
  }

  if (code === 'ETIMEDOUT' || code === 'ESOCKETTIMEDOUT') {
    return new Error(`${ERROR_CODES.EHTTPS_TIMEOUT}: Connection timed out - ${message}`);
  }

  if (message.includes('PIN_MISMATCH') || message.includes('pinning')) {
    return new Error(`${ERROR_CODES.EHTTPS_PIN_MISMATCH}: ${message}`);
  }

  if (
    message.includes('certificate') ||
    message.includes('CERT_') ||
    message.includes('SSL') ||
    message.includes('handshake') ||
    message.includes('TLS')
  ) {
    return new Error(getTlsErrorMessage(error));
  }

  return error;
}
