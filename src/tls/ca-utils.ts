/**
 * CA Certificate Utilities
 *
 * Functions for loading and managing CA certificates based on configured mode.
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import type { CaMode } from '../config/types.js';
import { ERROR_CODES } from '../constants.js';

// Get the directory of this module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Path to bundled Mozilla CA bundle
const BUNDLED_CA_PATH = path.join(__dirname, '../../ca-certificates/cacert.pem');

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
 * Get CA certificates based on the configured mode
 */
export function getCaCertificates(
  caMode: CaMode,
  customBundlePaths?: string[],
  additionalCaPaths?: string[]
): string | Buffer | (string | Buffer)[] {
  const caCerts: (string | Buffer)[] = [];

  switch (caMode) {
    case 'bundled':
      caCerts.push(loadBundledCa());
      break;

    case 'osPlusBundled':
      // Add bundled CAs; OS CAs are included via Node.js default when ca array is passed
      caCerts.push(loadBundledCa());
      break;

    case 'osOnly':
      // Return undefined to use Node.js default (OS CA store)
      break;

    case 'custom':
      if (!customBundlePaths || customBundlePaths.length === 0) {
        throw new Error(`${ERROR_CODES.EHTTPS_CA_LOAD_FAILED}: Custom CA bundle path is required`);
      }
      for (const caPath of customBundlePaths) {
        caCerts.push(loadCaFile(caPath));
      }
      break;
  }

  // Add additional CAs if provided
  if (additionalCaPaths && additionalCaPaths.length > 0) {
    for (const caPath of additionalCaPaths) {
      caCerts.push(loadCaFile(caPath));
    }
  }

  if (caCerts.length === 0) {
    return [];
  }

  if (caCerts.length === 1) {
    return caCerts[0];
  }

  return caCerts;
}

/**
 * Load the bundled Mozilla CA certificate store
 */
function loadBundledCa(): Buffer {
  try {
    // First try the installed location
    if (fs.existsSync(BUNDLED_CA_PATH)) {
      return fs.readFileSync(BUNDLED_CA_PATH);
    }

    // Try relative to current working directory (for development)
    const cwdPath = path.join(process.cwd(), 'ca-certificates', 'cacert.pem');
    if (fs.existsSync(cwdPath)) {
      return fs.readFileSync(cwdPath);
    }

    throw new Error(`Bundled CA file not found at ${BUNDLED_CA_PATH}`);
  } catch (error) {
    throw new Error(
      `${ERROR_CODES.EHTTPS_CA_LOAD_FAILED}: Failed to load bundled CA certificates: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
}

/**
 * Load a CA file from the specified path
 */
function loadCaFile(filePath: string): Buffer {
  try {
    const safePath = sanitizeFilePath(filePath);
    if (!fs.existsSync(safePath)) {
      throw new Error(`File not found: ${safePath}`);
    }
    return fs.readFileSync(safePath);
  } catch (error) {
    throw new Error(
      `${ERROR_CODES.EHTTPS_CA_LOAD_FAILED}: Failed to load CA file '${filePath}': ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
}
