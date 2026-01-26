/**
 * TLS Utilities
 *
 * Helper functions for TLS configuration, certificate handling,
 * and security validation.
 */

import * as tls from 'tls';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import type { TlsVersion, PinningMode } from '../config/types.js';
import { ERROR_CODES } from '../constants.js';

/**
 * Sanitize and validate a file path
 */
function sanitizeFilePath(filePath: string): string {
  if (filePath.includes('\0')) {
    throw new Error('Invalid file path: null bytes not allowed');
  }

  const normalizedPath = path.normalize(filePath);

  if (!path.isAbsolute(normalizedPath)) {
    throw new Error(`Invalid file path: must be an absolute path, got '${filePath}'`);
  }

  return normalizedPath;
}

/**
 * Validate TLS version configuration
 */
export function validateTlsVersions(minVersion: TlsVersion, maxVersion: TlsVersion): void {
  const versions: TlsVersion[] = ['TLSv1.2', 'TLSv1.3'];
  const minIndex = versions.indexOf(minVersion);
  const maxIndex = versions.indexOf(maxVersion);

  if (minIndex === -1) {
    throw new Error(`${ERROR_CODES.EHTTPS_TLS_HANDSHAKE}: Invalid minimum TLS version: ${minVersion}`);
  }

  if (maxIndex === -1) {
    throw new Error(`${ERROR_CODES.EHTTPS_TLS_HANDSHAKE}: Invalid maximum TLS version: ${maxVersion}`);
  }

  if (minIndex > maxIndex) {
    throw new Error(
      `${ERROR_CODES.EHTTPS_TLS_HANDSHAKE}: Minimum TLS version (${minVersion}) cannot be greater than maximum (${maxVersion})`
    );
  }
}

/**
 * Validate cipher string
 */
export function validateCiphers(ciphers: string, minVersion: TlsVersion): string {
  if (!ciphers || ciphers.trim() === '') {
    throw new Error(`${ERROR_CODES.EHTTPS_TLS_HANDSHAKE}: Cipher string cannot be empty`);
  }

  if (minVersion === 'TLSv1.3') {
    const tls13Ciphers = [
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
      'TLS_AES_128_GCM_SHA256',
    ];

    const hasTls13Cipher = tls13Ciphers.some((c) => ciphers.includes(c));
    if (!hasTls13Cipher) {
      throw new Error(
        `${ERROR_CODES.EHTTPS_TLS_HANDSHAKE}: When minimum TLS version is 1.3, cipher string must include TLS 1.3 ciphers`
      );
    }
  }

  return ciphers;
}

/**
 * Load a certificate from file
 */
export function loadCertificateFromFile(filePath: string): Buffer {
  try {
    const safePath = sanitizeFilePath(filePath);
    if (!fs.existsSync(safePath)) {
      throw new Error(`Certificate file not found: ${safePath}`);
    }
    return fs.readFileSync(safePath);
  } catch (error) {
    throw new Error(
      `Failed to load certificate from '${filePath}': ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Load a private key from file
 */
export function loadPrivateKeyFromFile(filePath: string): Buffer {
  try {
    const safePath = sanitizeFilePath(filePath);
    if (!fs.existsSync(safePath)) {
      throw new Error(`Private key file not found: ${safePath}`);
    }
    return fs.readFileSync(safePath);
  } catch (error) {
    throw new Error(
      `Failed to load private key from '${filePath}': ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * PKCS#12 OID constants
 */
const PKCS12_OIDS = {
  keyBag: '1.2.840.113549.1.12.10.1.1',
  pkcs8ShroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
  certBag: '1.2.840.113549.1.12.10.1.3',
  data: '1.2.840.113549.1.7.1',
  encryptedData: '1.2.840.113549.1.7.6',
  pbeWithSHA1And3KeyTripleDESCBC: '1.2.840.113549.1.12.1.3',
  pbeWithSHA1And40BitRC2CBC: '1.2.840.113549.1.12.1.6',
  x509Certificate: '1.2.840.113549.1.9.22.1',
};

/**
 * Simple ASN.1 DER parser
 */
interface Asn1Node {
  tag: number;
  tagClass: number;
  constructed: boolean;
  length: number;
  contents: Buffer;
  children?: Asn1Node[];
}

function parseAsn1(buffer: Buffer, offset: number = 0): { node: Asn1Node; bytesRead: number } {
  if (offset >= buffer.length) {
    throw new Error('Unexpected end of ASN.1 data');
  }

  const tagByte = buffer[offset];
  const tagClass = (tagByte & 0xc0) >> 6;
  const constructed = (tagByte & 0x20) !== 0;
  const tag = tagByte & 0x1f;

  const lengthOffset = offset + 1;
  let length: number;
  let headerLength: number;

  const lengthByte = buffer[lengthOffset];
  if (lengthByte < 0x80) {
    length = lengthByte;
    headerLength = 2;
  } else if (lengthByte === 0x80) {
    throw new Error('Indefinite length not supported');
  } else {
    const numOctets = lengthByte & 0x7f;
    length = 0;
    for (let i = 0; i < numOctets; i++) {
      length = (length << 8) | buffer[lengthOffset + 1 + i];
    }
    headerLength = 2 + numOctets;
  }

  const contentsOffset = offset + headerLength;
  const contents = buffer.subarray(contentsOffset, contentsOffset + length);

  const node: Asn1Node = {
    tag,
    tagClass,
    constructed,
    length,
    contents,
  };

  if (constructed) {
    node.children = [];
    let childOffset = 0;
    while (childOffset < contents.length) {
      const { node: child, bytesRead } = parseAsn1(contents, childOffset);
      node.children.push(child);
      childOffset += bytesRead;
    }
  }

  return { node, bytesRead: headerLength + length };
}

function parseOid(buffer: Buffer): string {
  const parts: number[] = [];
  parts.push(Math.floor(buffer[0] / 40));
  parts.push(buffer[0] % 40);

  let value = 0;
  for (let i = 1; i < buffer.length; i++) {
    value = (value << 7) | (buffer[i] & 0x7f);
    if ((buffer[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }

  return parts.join('.');
}

/**
 * Derive key from password using PKCS#12 KDF
 */
function pkcs12Kdf(
  password: string,
  salt: Buffer,
  iterations: number,
  keyLength: number,
  id: number
): Buffer {
  const passwordBuffer = Buffer.alloc((password.length + 1) * 2);
  for (let i = 0; i < password.length; i++) {
    passwordBuffer.writeUInt16BE(password.charCodeAt(i), i * 2);
  }

  const u = 20;
  const v = 64;

  const D = Buffer.alloc(v, id);

  const sLen = v * Math.ceil(salt.length / v);
  const pLen = v * Math.ceil(passwordBuffer.length / v);
  const I = Buffer.alloc(sLen + pLen);

  for (let i = 0; i < sLen; i++) {
    I[i] = salt[i % salt.length];
  }
  for (let i = 0; i < pLen; i++) {
    I[sLen + i] = passwordBuffer[i % passwordBuffer.length];
  }

  const c = Math.ceil(keyLength / u);
  const result = Buffer.alloc(c * u);

  for (let i = 0; i < c; i++) {
    let A = Buffer.concat([D, I]);
    for (let j = 0; j < iterations; j++) {
      A = crypto.createHash('sha1').update(A).digest();
    }

    A.copy(result, i * u);

    if (i < c - 1) {
      const B = Buffer.alloc(v);
      for (let j = 0; j < v; j++) {
        B[j] = A[j % A.length];
      }

      for (let j = 0; j < I.length / v; j++) {
        let carry = 1;
        for (let k = v - 1; k >= 0; k--) {
          const sum = I[j * v + k] + B[k] + carry;
          I[j * v + k] = sum & 0xff;
          carry = sum >> 8;
        }
      }
    }
  }

  return result.subarray(0, keyLength);
}

/**
 * Decrypt PKCS#12 encrypted data
 */
function decryptPkcs12Data(
  encryptedData: Buffer,
  password: string,
  algorithmOid: string,
  salt: Buffer,
  iterations: number
): Buffer {
  let keyLength: number;
  let ivLength: number;
  let algorithm: string;

  if (algorithmOid === PKCS12_OIDS.pbeWithSHA1And3KeyTripleDESCBC) {
    keyLength = 24;
    ivLength = 8;
    algorithm = 'des-ede3-cbc';
  } else if (algorithmOid === PKCS12_OIDS.pbeWithSHA1And40BitRC2CBC) {
    keyLength = 5;
    ivLength = 8;
    algorithm = 'rc2-40-cbc';
  } else {
    throw new Error(`Unsupported PKCS#12 encryption algorithm: ${algorithmOid}`);
  }

  const key = pkcs12Kdf(password, salt, iterations, keyLength, 1);
  const iv = pkcs12Kdf(password, salt, iterations, ivLength, 2);

  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
}

/**
 * Parse a PKCS#12 safe bag to extract cert or key
 */
function parseSafeBag(safeBag: Asn1Node, password: string): { cert?: string; key?: string } {
  if (!safeBag.children || safeBag.children.length < 2) {
    return {};
  }

  const bagTypeOid = parseOid(safeBag.children[0].contents);
  const bagValue = safeBag.children[1];

  if (bagTypeOid === PKCS12_OIDS.certBag && bagValue.children) {
    const certBag = bagValue.children[0];
    if (!certBag.children || certBag.children.length < 2) return {};

    const certTypeOid = parseOid(certBag.children[0].contents);
    if (certTypeOid === PKCS12_OIDS.x509Certificate) {
      const certValue = certBag.children[1];
      if (certValue.children) {
        const certDer = certValue.children[0].contents;
        const certBase64 = certDer.toString('base64');
        const certPem = `-----BEGIN CERTIFICATE-----\n${certBase64.match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----`;
        return { cert: certPem };
      }
    }
  } else if (bagTypeOid === PKCS12_OIDS.pkcs8ShroudedKeyBag && bagValue.children) {
    const shroudedKey = bagValue.children[0];
    if (!shroudedKey.children || shroudedKey.children.length < 2) return {};

    const algoSeq = shroudedKey.children[0];
    if (!algoSeq.children || algoSeq.children.length < 2) return {};

    const algorithmOid = parseOid(algoSeq.children[0].contents);
    const algoParams = algoSeq.children[1];
    if (!algoParams.children || algoParams.children.length < 2) return {};

    const salt = algoParams.children[0].contents;
    const iterations = parseInt(algoParams.children[1].contents.toString('hex'), 16);

    const encryptedKey = shroudedKey.children[1].contents;

    const decryptedKey = decryptPkcs12Data(encryptedKey, password, algorithmOid, salt, iterations);

    const keyBase64 = decryptedKey.toString('base64');
    const keyPem = `-----BEGIN PRIVATE KEY-----\n${keyBase64.match(/.{1,64}/g)?.join('\n')}\n-----END PRIVATE KEY-----`;
    return { key: keyPem };
  } else if (bagTypeOid === PKCS12_OIDS.keyBag && bagValue.children) {
    const keyDer = bagValue.children[0].contents;
    const keyBase64 = keyDer.toString('base64');
    const keyPem = `-----BEGIN PRIVATE KEY-----\n${keyBase64.match(/.{1,64}/g)?.join('\n')}\n-----END PRIVATE KEY-----`;
    return { key: keyPem };
  }

  return {};
}

/**
 * Parse PKCS#12 file to extract certificate and key
 */
export function parsePkcs12(p12Buffer: Buffer, password: string): { cert: Buffer; key: Buffer } {
  try {
    const { node: pfx } = parseAsn1(p12Buffer);

    if (!pfx.children || pfx.children.length < 2) {
      throw new Error('Invalid PKCS#12 structure');
    }

    const authSafeContent = pfx.children[1];
    if (!authSafeContent.children) {
      throw new Error('Invalid PKCS#12 authenticated safe');
    }

    let certPem: string | null = null;
    let keyPem: string | null = null;

    const authSafeData = authSafeContent.children[1];
    if (authSafeData.tag === 4) {
      const { node: authSafeSeq } = parseAsn1(authSafeData.contents);

      if (authSafeSeq.children) {
        for (const contentInfo of authSafeSeq.children) {
          if (!contentInfo.children || contentInfo.children.length < 2) continue;

          const contentTypeOid = parseOid(contentInfo.children[0].contents);
          const content = contentInfo.children[1];

          if (contentTypeOid === PKCS12_OIDS.data && content.children) {
            const octetString = content.children[0];
            const { node: safeContents } = parseAsn1(octetString.contents);

            if (safeContents.children) {
              for (const safeBag of safeContents.children) {
                const bagResult = parseSafeBag(safeBag, password);
                if (bagResult.cert) certPem = bagResult.cert;
                if (bagResult.key) keyPem = bagResult.key;
              }
            }
          } else if (contentTypeOid === PKCS12_OIDS.encryptedData && content.children) {
            const encryptedDataSeq = content.children[0];
            if (!encryptedDataSeq.children) continue;

            const encContentInfo = encryptedDataSeq.children[1];
            if (!encContentInfo.children || encContentInfo.children.length < 3) continue;

            const encAlgoSeq = encContentInfo.children[1];
            if (!encAlgoSeq.children || encAlgoSeq.children.length < 2) continue;

            const algorithmOid = parseOid(encAlgoSeq.children[0].contents);
            const algoParams = encAlgoSeq.children[1];
            if (!algoParams.children || algoParams.children.length < 2) continue;

            const salt = algoParams.children[0].contents;
            const iterations = parseInt(algoParams.children[1].contents.toString('hex'), 16);

            const encryptedContent = encContentInfo.children[2].contents;

            const decrypted = decryptPkcs12Data(encryptedContent, password, algorithmOid, salt, iterations);

            const { node: safeContents } = parseAsn1(decrypted);
            if (safeContents.children) {
              for (const safeBag of safeContents.children) {
                const bagResult = parseSafeBag(safeBag, password);
                if (bagResult.cert) certPem = bagResult.cert;
                if (bagResult.key) keyPem = bagResult.key;
              }
            }
          }
        }
      }
    }

    if (!certPem || !keyPem) {
      throw new Error('Could not extract certificate and key from PKCS#12 file');
    }

    return {
      cert: Buffer.from(certPem, 'utf8'),
      key: Buffer.from(keyPem, 'utf8'),
    };
  } catch (error) {
    if (error instanceof Error && error.message.includes('PKCS#12')) {
      throw error;
    }
    throw new Error(
      `Failed to parse PKCS#12 file: ${error instanceof Error ? error.message : String(error)}. ` +
        'If this error persists, convert to PEM format using: ' +
        'openssl pkcs12 -in certificate.p12 -out certificate.pem -nodes'
    );
  }
}

/**
 * Compute SPKI hash for a certificate
 */
export function computeSpkiHash(certPem: string | Buffer): string {
  const cert = new crypto.X509Certificate(certPem);
  const publicKey = cert.publicKey;
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const hash = crypto.createHash('sha256').update(spkiDer).digest('base64');
  return `sha256/${hash}`;
}

/**
 * Verify certificate against pinned values
 */
export function verifyCertificatePin(
  certChain: crypto.X509Certificate[],
  pins: string[],
  mode: PinningMode
): { valid: boolean; error?: string } {
  if (certChain.length === 0) {
    return { valid: false, error: 'No certificates in chain' };
  }

  let certToCheck: crypto.X509Certificate;

  switch (mode) {
    case 'leaf':
      certToCheck = certChain[0];
      break;

    case 'intermediate':
      if (certChain.length < 2) {
        return { valid: false, error: 'No intermediate certificate in chain' };
      }
      certToCheck = certChain[1];
      break;

    case 'root':
      certToCheck = certChain[certChain.length - 1];
      break;

    case 'spki':
      for (const cert of certChain) {
        const spkiHash = computeSpkiHash(cert.toString());
        if (pins.includes(spkiHash)) {
          return { valid: true };
        }
      }
      return {
        valid: false,
        error: `${ERROR_CODES.EHTTPS_PIN_MISMATCH}: No certificate in chain matches any pinned SPKI hash`,
      };

    default:
      return { valid: false, error: `Unknown pinning mode: ${String(mode)}` };
  }

  const certSpki = computeSpkiHash(certToCheck.toString());

  for (const pin of pins) {
    if (pin.startsWith('sha256/')) {
      if (certSpki === pin) {
        return { valid: true };
      }
    } else if (pin.includes('BEGIN CERTIFICATE')) {
      try {
        const pinSpki = computeSpkiHash(pin);
        if (certSpki === pinSpki) {
          return { valid: true };
        }
      } catch {
        // Invalid PEM, skip
      }
    }
  }

  return {
    valid: false,
    error: `${ERROR_CODES.EHTTPS_PIN_MISMATCH}: Certificate does not match any pinned value`,
  };
}

/**
 * Load pinned certificates from file
 */
export function loadPinsFromFile(filePath: string): string[] {
  const content = loadCertificateFromFile(filePath).toString('utf8');

  if (content.includes('BEGIN CERTIFICATE')) {
    const certs: string[] = [];
    const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
    let match;
    while ((match = regex.exec(content)) !== null) {
      certs.push(match[0]);
    }
    return certs;
  }

  return content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
}

/**
 * Create a custom checkServerIdentity function for certificate pinning
 */
export function createPinningCheckFunction(
  pins: string[],
  mode: PinningMode
): (hostname: string, cert: tls.PeerCertificate) => Error | undefined {
  return (hostname: string, cert: tls.PeerCertificate): Error | undefined => {
    const standardError = tls.checkServerIdentity(hostname, cert);
    if (standardError) {
      return standardError;
    }

    try {
      const certChain: crypto.X509Certificate[] = [];

      if (cert.raw) {
        certChain.push(new crypto.X509Certificate(cert.raw));
      }

      let currentCert = cert as tls.DetailedPeerCertificate;
      while (currentCert.issuerCertificate && currentCert.issuerCertificate !== currentCert) {
        if (currentCert.issuerCertificate.raw) {
          certChain.push(new crypto.X509Certificate(currentCert.issuerCertificate.raw));
        }
        currentCert = currentCert.issuerCertificate;
      }

      const pinResult = verifyCertificatePin(certChain, pins, mode);
      if (!pinResult.valid) {
        return new Error(pinResult.error || 'Certificate pinning failed');
      }
    } catch (error) {
      return new Error(
        `Certificate pinning verification failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    return undefined;
  };
}

/**
 * Get human-readable TLS error message
 */
export function getTlsErrorMessage(error: Error): string {
  const message = error.message;

  if (message.includes('CERT_HAS_EXPIRED')) {
    return `${ERROR_CODES.EHTTPS_CERT_EXPIRED}: Server certificate has expired`;
  }

  if (message.includes('CERT_NOT_YET_VALID')) {
    return `${ERROR_CODES.EHTTPS_CERT_NOT_YET_VALID}: Server certificate is not yet valid`;
  }

  if (message.includes('UNABLE_TO_VERIFY_LEAF_SIGNATURE') || message.includes('SELF_SIGNED_CERT_IN_CHAIN')) {
    return `${ERROR_CODES.EHTTPS_CERT_VERIFY}: Unable to verify certificate - check CA configuration`;
  }

  if (message.includes('HOSTNAME_MISMATCH') || message.includes('ERR_TLS_CERT_ALTNAME_INVALID')) {
    return `${ERROR_CODES.EHTTPS_HOSTNAME_MISMATCH}: Certificate hostname mismatch`;
  }

  if (message.includes('DEPTH_ZERO_SELF_SIGNED_CERT')) {
    return `${ERROR_CODES.EHTTPS_CERT_VERIFY}: Self-signed certificate not trusted`;
  }

  if (message.includes('CERT_REVOKED')) {
    return `${ERROR_CODES.EHTTPS_CERT_REVOKED}: Server certificate has been revoked`;
  }

  if (message.includes('handshake') || message.includes('SSL')) {
    return `${ERROR_CODES.EHTTPS_TLS_HANDSHAKE}: TLS handshake failed - ${message}`;
  }

  return `${ERROR_CODES.EHTTPS_CERT_VERIFY}: ${message}`;
}
