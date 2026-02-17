import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DEFAULT_CONFIG, getConfigPath, loadConfig, validateConfig, loadAndValidateConfig } from '../config/loader.js';
import type { HttpsConfig } from '../config/types.js';

vi.mock('fs');
vi.mock('os');

function makeConfig(overrides: Record<string, unknown> = {}): HttpsConfig {
  const config = JSON.parse(JSON.stringify(DEFAULT_CONFIG)) as HttpsConfig;
  for (const [key, value] of Object.entries(overrides)) {
    const parts = key.split('.');
    let target: Record<string, unknown> = config as unknown as Record<string, unknown>;
    for (let i = 0; i < parts.length - 1; i++) {
      target = target[parts[i]] as Record<string, unknown>;
    }
    target[parts[parts.length - 1]] = value;
  }
  return config;
}

describe('validateConfig', () => {
  it('returns no errors for valid default config', () => {
    expect(validateConfig(DEFAULT_CONFIG)).toEqual([]);
  });

  it('rejects invalid tls.minVersion', () => {
    const config = makeConfig({ 'tls.minVersion': 'TLSv1.0' });
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('tls.minVersion'));
  });

  it('rejects invalid tls.maxVersion', () => {
    const config = makeConfig({ 'tls.maxVersion': 'TLSv1.4' });
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('tls.maxVersion'));
  });

  it('rejects invalid tls.cipherProfile', () => {
    const config = makeConfig({ 'tls.cipherProfile': 'superstrong' });
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('tls.cipherProfile'));
  });

  it('rejects invalid ca.mode', () => {
    const config = makeConfig({ 'ca.mode': 'invalid' });
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('ca.mode'));
  });

  it('rejects custom ca.mode without customBundlePaths', () => {
    const config = makeConfig({ 'ca.mode': 'custom' });
    config.ca.customBundlePaths = [];
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('customBundlePaths'));
  });

  it('accepts custom ca.mode with customBundlePaths', () => {
    const config = makeConfig({ 'ca.mode': 'custom' });
    config.ca.customBundlePaths = ['/path/to/ca.pem'];
    const errors = validateConfig(config);
    expect(errors).toEqual([]);
  });

  it('rejects invalid pinning.mode when enabled', () => {
    const config = makeConfig({ 'pinning.enabled': true, 'pinning.mode': 'invalid' });
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('pinning.mode'));
  });

  it('accepts invalid pinning.mode when disabled', () => {
    const config = makeConfig({ 'pinning.enabled': false, 'pinning.mode': 'invalid' });
    const errors = validateConfig(config);
    expect(errors).toEqual([]);
  });

  it('rejects invalid revocation.policy when enabled', () => {
    const config = makeConfig({ 'revocation.enabled': true, 'revocation.policy': 'invalid' });
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('revocation.policy'));
  });

  it('rejects invalid revocation.failMode when enabled', () => {
    const config = makeConfig({ 'revocation.enabled': true, 'revocation.failMode': 'medium' });
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('revocation.failMode'));
  });

  it('rejects invalid proxy.auth.type when enabled', () => {
    const config = makeConfig({ 'proxy.enabled': true });
    config.proxy.url = 'http://proxy:8080';
    config.proxy.auth.type = 'kerberos' as never;
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('proxy.auth.type'));
  });

  it('rejects proxy.enabled without url', () => {
    const config = makeConfig({ 'proxy.enabled': true });
    config.proxy.url = null;
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('proxy.url'));
  });

  it('rejects non-positive timeout', () => {
    const config = makeConfig({ 'defaults.timeoutMs': 0 });
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('timeoutMs'));
  });

  it('rejects negative maxRedirects', () => {
    const config = makeConfig({ 'defaults.maxRedirects': -1 });
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('maxRedirects'));
  });

  it('accepts zero maxRedirects', () => {
    const config = makeConfig({ 'defaults.maxRedirects': 0 });
    const errors = validateConfig(config);
    expect(errors).toEqual([]);
  });

  it('rejects non-positive maxBodySizeBytes', () => {
    const config = makeConfig({ 'defaults.maxBodySizeBytes': 0 });
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('maxBodySizeBytes'));
  });

  it('rejects negative maxBodySizeBytes', () => {
    const config = makeConfig({ 'defaults.maxBodySizeBytes': -1 });
    const errors = validateConfig(config);
    expect(errors).toContainEqual(expect.stringContaining('maxBodySizeBytes'));
  });

  it('accepts positive maxBodySizeBytes', () => {
    const config = makeConfig({ 'defaults.maxBodySizeBytes': 1024 });
    const errors = validateConfig(config);
    expect(errors).toEqual([]);
  });

  it('has 10MB default maxBodySizeBytes', () => {
    expect(DEFAULT_CONFIG.defaults.maxBodySizeBytes).toBe(10 * 1024 * 1024);
  });
});

describe('getConfigPath', () => {
  const originalEnv = process.env.CLAUDE_HTTPS_CONFIG;

  afterEach(() => {
    if (originalEnv !== undefined) {
      process.env.CLAUDE_HTTPS_CONFIG = originalEnv;
    } else {
      delete process.env.CLAUDE_HTTPS_CONFIG;
    }
  });

  it('returns env path when CLAUDE_HTTPS_CONFIG is set', () => {
    process.env.CLAUDE_HTTPS_CONFIG = '/custom/path.json';
    expect(getConfigPath()).toBe('/custom/path.json');
  });

  it('returns default path when no env var', () => {
    delete process.env.CLAUDE_HTTPS_CONFIG;
    vi.mocked(os.homedir).mockReturnValue('/home/user');
    expect(getConfigPath()).toBe(path.join('/home/user', '.claude', 'https-config.json'));
  });
});

describe('loadConfig', () => {
  beforeEach(() => {
    vi.mocked(os.homedir).mockReturnValue('/home/user');
    delete process.env.CLAUDE_HTTPS_CONFIG;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns default config when file does not exist', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    const config = loadConfig();
    expect(config.tls.cipherProfile).toBe('intermediate');
    expect(config.defaults.timeoutMs).toBe(30000);
  });

  it('merges partial user config with defaults', () => {
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockReturnValue(
      JSON.stringify({ tls: { cipherProfile: 'modern' } })
    );
    const config = loadConfig();
    expect(config.tls.cipherProfile).toBe('modern');
    expect(config.tls.minVersion).toBe('TLSv1.2'); // default preserved
    expect(config.defaults.timeoutMs).toBe(30000); // default preserved
  });

  it('deep merges proxy.auth', () => {
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockReturnValue(
      JSON.stringify({ proxy: { enabled: true, url: 'http://proxy:8080', auth: { type: 'basic', username: 'user' } } })
    );
    const config = loadConfig();
    expect(config.proxy.auth.type).toBe('basic');
    expect(config.proxy.auth.username).toBe('user');
    expect(config.proxy.auth.password).toBeNull(); // default preserved
  });

  it('throws on malformed JSON', () => {
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockReturnValue('{invalid json');
    expect(() => loadConfig()).toThrow('EHTTPS_CONFIG_INVALID');
  });
});

describe('loadAndValidateConfig', () => {
  beforeEach(() => {
    vi.mocked(os.homedir).mockReturnValue('/home/user');
    delete process.env.CLAUDE_HTTPS_CONFIG;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns config when valid', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    const config = loadAndValidateConfig();
    expect(config).toBeDefined();
    expect(config.tls.minVersion).toBe('TLSv1.2');
  });

  it('throws when validation fails', () => {
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockReturnValue(
      JSON.stringify({ tls: { minVersion: 'TLSv1.0' } })
    );
    expect(() => loadAndValidateConfig()).toThrow('EHTTPS_CONFIG_INVALID');
  });
});
