/**
 * Configuration loader for the Claude HTTPS MCP tool
 * Loads and validates configuration from ~/.claude/https-config.json
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { HttpsConfig } from './types.js';
import { ERROR_CODES } from '../constants.js';

/**
 * Default configuration values
 */
export const DEFAULT_CONFIG: HttpsConfig = {
  tls: {
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    cipherProfile: 'intermediate',
    customCiphers: null,
    rejectUnauthorized: true,
  },
  ca: {
    mode: 'bundled',
    customBundlePaths: [],
    additionalCaPaths: [],
  },
  clientCert: {
    enabled: false,
    certPath: null,
    keyPath: null,
    passphrase: null,
    p12Path: null,
    p12Passphrase: null,
  },
  pinning: {
    enabled: false,
    mode: 'leaf',
    pins: [],
  },
  revocation: {
    enabled: false,
    policy: 'ocspWithCrlFallback',
    failMode: 'soft',
    customOcspUrl: null,
    customCrlUrl: null,
    enableStapling: false,
    cacheTtlSeconds: 300,
  },
  proxy: {
    enabled: false,
    url: null,
    auth: {
      type: 'none',
      username: null,
      password: null,
      ntlmDomain: null,
    },
    bypassList: [],
  },
  defaults: {
    timeoutMs: 30000,
    followRedirects: true,
    maxRedirects: 10,
  },
  license: {
    key: null,
  },
};

/**
 * Get the path to the config file
 */
export function getConfigPath(): string {
  // Check for environment variable override
  const envPath = process.env.CLAUDE_HTTPS_CONFIG;
  if (envPath) {
    return envPath;
  }

  // Default to ~/.claude/https-config.json
  return path.join(os.homedir(), '.claude', 'https-config.json');
}

/**
 * Load configuration from file
 * Returns default config if file doesn't exist
 */
export function loadConfig(): HttpsConfig {
  const configPath = getConfigPath();

  // Check if config file exists
  if (!fs.existsSync(configPath)) {
    // Return default config if file doesn't exist
    return { ...DEFAULT_CONFIG };
  }

  try {
    const content = fs.readFileSync(configPath, 'utf8');
    const userConfig = JSON.parse(content) as Partial<HttpsConfig>;

    // Deep merge user config with defaults
    return mergeConfig(DEFAULT_CONFIG, userConfig);
  } catch (error) {
    throw new Error(
      `${ERROR_CODES.EHTTPS_CONFIG_INVALID}: Failed to load config from ${configPath}: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
}

/**
 * Deep merge configuration objects
 */
function mergeConfig(
  defaults: HttpsConfig,
  userConfig: Partial<HttpsConfig>
): HttpsConfig {
  return {
    tls: {
      ...defaults.tls,
      ...(userConfig.tls || {}),
    },
    ca: {
      ...defaults.ca,
      ...(userConfig.ca || {}),
    },
    clientCert: {
      ...defaults.clientCert,
      ...(userConfig.clientCert || {}),
    },
    pinning: {
      ...defaults.pinning,
      ...(userConfig.pinning || {}),
    },
    revocation: {
      ...defaults.revocation,
      ...(userConfig.revocation || {}),
    },
    proxy: {
      ...defaults.proxy,
      ...(userConfig.proxy || {}),
      auth: {
        ...defaults.proxy.auth,
        ...(userConfig.proxy?.auth || {}),
      },
    },
    defaults: {
      ...defaults.defaults,
      ...(userConfig.defaults || {}),
    },
    license: {
      ...defaults.license,
      ...(userConfig.license || {}),
    },
  };
}

/**
 * Validate configuration
 */
export function validateConfig(config: HttpsConfig): string[] {
  const errors: string[] = [];

  // Validate TLS versions
  const validTlsVersions = ['TLSv1.2', 'TLSv1.3'];
  if (!validTlsVersions.includes(config.tls.minVersion)) {
    errors.push(`Invalid tls.minVersion: ${config.tls.minVersion}`);
  }
  if (!validTlsVersions.includes(config.tls.maxVersion)) {
    errors.push(`Invalid tls.maxVersion: ${config.tls.maxVersion}`);
  }

  // Validate cipher profile
  const validProfiles = ['modern', 'intermediate', 'compatible', 'fips', 'custom'];
  if (!validProfiles.includes(config.tls.cipherProfile)) {
    errors.push(`Invalid tls.cipherProfile: ${config.tls.cipherProfile}`);
  }

  // Validate CA mode
  const validCaModes = ['bundled', 'osPlusBundled', 'osOnly', 'custom'];
  if (!validCaModes.includes(config.ca.mode)) {
    errors.push(`Invalid ca.mode: ${config.ca.mode}`);
  }

  // Validate custom CA paths if mode is 'custom'
  if (config.ca.mode === 'custom' && config.ca.customBundlePaths.length === 0) {
    errors.push('ca.customBundlePaths is required when ca.mode is "custom"');
  }

  // Validate pinning mode
  const validPinningModes = ['leaf', 'intermediate', 'root', 'spki'];
  if (config.pinning.enabled && !validPinningModes.includes(config.pinning.mode)) {
    errors.push(`Invalid pinning.mode: ${config.pinning.mode}`);
  }

  // Validate revocation policy
  const validPolicies = ['ocspWithCrlFallback', 'ocspOnly', 'crlOnly', 'bothRequired'];
  if (config.revocation.enabled && !validPolicies.includes(config.revocation.policy)) {
    errors.push(`Invalid revocation.policy: ${config.revocation.policy}`);
  }

  // Validate fail mode
  const validFailModes = ['soft', 'hard'];
  if (config.revocation.enabled && !validFailModes.includes(config.revocation.failMode)) {
    errors.push(`Invalid revocation.failMode: ${config.revocation.failMode}`);
  }

  // Validate proxy auth type
  const validAuthTypes = ['none', 'basic', 'digest', 'ntlm'];
  if (config.proxy.enabled && !validAuthTypes.includes(config.proxy.auth.type)) {
    errors.push(`Invalid proxy.auth.type: ${config.proxy.auth.type}`);
  }

  // Validate proxy URL if enabled
  if (config.proxy.enabled && !config.proxy.url) {
    errors.push('proxy.url is required when proxy.enabled is true');
  }

  // Validate timeout
  if (config.defaults.timeoutMs <= 0) {
    errors.push('defaults.timeoutMs must be positive');
  }

  // Validate maxRedirects
  if (config.defaults.maxRedirects < 0) {
    errors.push('defaults.maxRedirects cannot be negative');
  }

  return errors;
}

/**
 * Load and validate configuration
 * Throws if configuration is invalid
 */
export function loadAndValidateConfig(): HttpsConfig {
  const config = loadConfig();
  const errors = validateConfig(config);

  if (errors.length > 0) {
    throw new Error(
      `${ERROR_CODES.EHTTPS_CONFIG_INVALID}: Configuration validation failed:\n${errors.join('\n')}`
    );
  }

  return config;
}
