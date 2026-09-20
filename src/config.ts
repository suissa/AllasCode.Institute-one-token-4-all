import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { load as loadYaml } from 'js-yaml';

/**
 * Schema for `configs/core.yml`. Protocol-mandated values are NOT here — they
 * are hardcoded in source (see RFC 9449 §4.2 + §6.1).
 */
export interface CoreConfig {
  crypto: {
    random: {
      minByteLength: number;
      defaultByteLength: number;
    };
    pkce: {
      verifierByteLength: number;
    };
    keypair: {
      curve: 'P-256';
      hash: 'SHA-256';
      extractablePrivate: false;
    };
  };
  proof: {
    jti: {
      randomByteLength: number;
    };
    iat: {
      clockSkewSeconds: number;
    };
  };
  client: {
    http: {
      defaultMethod: 'POST';
      timeoutMs: number;
    };
    nonce: {
      maxRetries: number;
    };
    ephemeralKeys: boolean;
  };
  security: {
    immediateKeyWipe: boolean;
    requireClientId: boolean;
  };
  benchmark: {
    warmupIterations: number;
    measurementIterations: number;
  };
  load: {
    parallelProofs: number;
  };
  stress: {
    keygenCycles: number;
  };
}

/** Frozen baseline used when no YAML is supplied or fields are missing. */
export const defaultConfig: Readonly<CoreConfig> = Object.freeze({
  crypto: {
    random: { minByteLength: 16, defaultByteLength: 32 },
    pkce: { verifierByteLength: 32 },
    keypair: { curve: 'P-256' as const, hash: 'SHA-256' as const, extractablePrivate: false as const },
  },
  proof: {
    jti: { randomByteLength: 24 },
    iat: { clockSkewSeconds: 30 },
  },
  client: {
    http: { defaultMethod: 'POST' as const, timeoutMs: 30_000 },
    nonce: { maxRetries: 1 },
    ephemeralKeys: false,
  },
  security: {
    immediateKeyWipe: true,
    requireClientId: true,
  },
  benchmark: {
    warmupIterations: 50,
    measurementIterations: 500,
  },
  load: { parallelProofs: 100 },
  stress: { keygenCycles: 200 },
});

/**
 * Deep-merge `overrides` onto `base`. Replaces objects/arrays (does not merge
 * them). Used by `loadConfig` to layer YAML on top of defaults.
 *
 * The cast chain preserves literal types from `defaultConfig` only at the top
 * level — literal narrowing through nested generics is not preserved by
 * TypeScript, so we re-assert the final shape as `CoreConfig`.
 */
function mergeDeep(base: unknown, overrides: unknown): unknown {
  if (overrides === undefined || overrides === null) return base;
  if (typeof base !== 'object' || base === null || Array.isArray(base)) {
    return overrides ?? base;
  }
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  const o = overrides as Record<string, unknown>;
  for (const k of Object.keys(o)) {
    const b = (base as Record<string, unknown>)[k];
    const v = o[k];
    out[k] =
      b !== undefined && typeof b === 'object' && b !== null && !Array.isArray(b) &&
      typeof v === 'object' && v !== null && !Array.isArray(v)
        ? mergeDeep(b, v)
        : v;
  }
  return out;
}

/**
 * Load a YAML config file, layer it on top of `defaultConfig`, then enforce
 * the security invariants the source code cannot break silently:
 *
 *   - `crypto.keypair.curve` MUST be 'P-256' (RFC 9449 §4.1).
 *   - `crypto.keypair.hash` MUST be 'SHA-256'.
 *   - `crypto.keypair.extractablePrivate` MUST be `false`.
 *   - `crypto.keypair` literal type keeps the loader honest; if a user adds a
 *     new value to YAML we throw rather than silently substituting.
 */
export function loadConfig(path?: string): CoreConfig {
  let fileOverrides: Partial<CoreConfig> = {};
  if (path !== undefined) {
    const abs = resolve(path);
    const raw = readFileSync(abs, 'utf8');
    const parsed = loadYaml(raw) as Record<string, unknown> | null;
    if (parsed && typeof parsed === 'object') {
      fileOverrides = enforceConfigInvariants(parsed);
    }
  }

  return mergeDeep(defaultConfig, fileOverrides) as CoreConfig;
}

/**
 * Validate YAML-derived overrides against the protocol-mandated literal types.
 * Throws loudly rather than silently substituting defaults — a misconfigured
 * file should fail at startup, not at the first token request.
 */
function enforceConfigInvariants(raw: Record<string, unknown>): Partial<CoreConfig> {
  const crypto_ = raw['crypto'] as Record<string, unknown> | undefined;
  const keypair = crypto_?.['keypair'] as Record<string, unknown> | undefined;
  if (keypair) {
    if (keypair['curve'] !== undefined && keypair['curve'] !== 'P-256') {
      throw new Error(`config: crypto.keypair.curve must be 'P-256' (got '${String(keypair['curve'])}')`);
    }
    if (keypair['hash'] !== undefined && keypair['hash'] !== 'SHA-256') {
      throw new Error(`config: crypto.keypair.hash must be 'SHA-256' (got '${String(keypair['hash'])}')`);
    }
    if (keypair['extractablePrivate'] === true) {
      throw new Error('config: crypto.keypair.extractablePrivate MUST be false (security guardrail)');
    }
  }
  // Hand the rest back as-is; mergeDeep will layer onto the typed defaults.
  return raw as Partial<CoreConfig>;
}

/** Convenience: read-only view of the active config in DPoPClient etc. */
export function freezeConfig(c: CoreConfig): Readonly<CoreConfig> {
  return Object.freeze(c);
}
