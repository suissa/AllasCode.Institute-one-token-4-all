import { describe, it, expect } from 'vitest';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadConfig, defaultConfig, freezeConfig } from '../src/config.js';

describe('defaultConfig', () => {
  it('freezes to protocol-mandated literals', () => {
    expect(defaultConfig.crypto.keypair.curve).toBe('P-256');
    expect(defaultConfig.crypto.keypair.hash).toBe('SHA-256');
    expect(defaultConfig.crypto.keypair.extractablePrivate).toBe(false);
  });

  it('is frozen — cannot be mutated', () => {
    expect(Object.isFrozen(defaultConfig)).toBe(true);
  });
});

describe('loadConfig', () => {
  it('returns defaultConfig when no path supplied', () => {
    const cfg = loadConfig();
    expect(cfg).toEqual(defaultConfig);
  });

  it('reads and merges a YAML file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cfg-'));
    const file = join(dir, 'core.yml');
    writeFileSync(
      file,
      [
        'client:',
        '  nonce:',
        '    maxRetries: 3',
        '  ephemeralKeys: true',
        'benchmark:',
        '  warmupIterations: 10',
      ].join('\n'),
    );
    const cfg = loadConfig(file);
    expect(cfg.client.nonce.maxRetries).toBe(3);
    expect(cfg.client.ephemeralKeys).toBe(true);
    expect(cfg.benchmark.warmupIterations).toBe(10);
    // unchanged defaults preserved
    expect(cfg.crypto.keypair.curve).toBe('P-256');
    rmSync(dir, { recursive: true });
  });

  it('throws when YAML violates RFC-mandated curve', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cfg-'));
    const file = join(dir, 'core.yml');
    writeFileSync(file, 'crypto:\n  keypair:\n    curve: P-384\n');
    expect(() => loadConfig(file)).toThrow(/curve must be 'P-256'/);
    rmSync(dir, { recursive: true });
  });

  it('throws when YAML tries to make the private key extractable', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cfg-'));
    const file = join(dir, 'core.yml');
    writeFileSync(file, 'crypto:\n  keypair:\n    extractablePrivate: true\n');
    expect(() => loadConfig(file)).toThrow(/extractablePrivate MUST be false/);
    rmSync(dir, { recursive: true });
  });

  it('throws when YAML violates RFC-mandated hash', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cfg-'));
    const file = join(dir, 'core.yml');
    writeFileSync(file, 'crypto:\n  keypair:\n    hash: SHA-512\n');
    expect(() => loadConfig(file)).toThrow(/hash must be 'SHA-256'/);
    rmSync(dir, { recursive: true });
  });
});

describe('freezeConfig', () => {
  it('returns a frozen object', () => {
    const cfg = freezeConfig(defaultConfig);
    expect(Object.isFrozen(cfg)).toBe(true);
  });
});
