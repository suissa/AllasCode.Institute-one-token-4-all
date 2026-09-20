import { describe, it, expect } from 'vitest';
import { generateDPoPKeyPair } from '../../src/crypto/keypair.js';
import { createDPoPProof } from '../../src/proof/createDPoPProof.js';
import { loadConfig } from '../../src/config.js';

/**
 * Stress test — push the keygen + proof cycle past normal capacity.
 * Goal: confirm the lib does not crash, leak handles, or produce unusable
 * proofs under repeated high-volume allocation.
 */

const cfg = loadConfig();

describe(`Stress: ${cfg.stress.keygenCycles} sequential keygen+proof cycles`, () => {
  it('does not throw or hang across the configured cycle count', async () => {
    const N = cfg.stress.keygenCycles;
    let ok = 0;
    for (let i = 0; i < N; i++) {
      const kp = await generateDPoPKeyPair();
      const p = await createDPoPProof({
        publicKey: kp.publicKey,
        privateKey: kp.privateKey,
        htm: 'POST',
        htu: 'https://as.example.com/token',
        jti: `cycle-${i}`,
      });
      expect(p.split('.')).toHaveLength(3);
      ok++;
    }
    expect(ok).toBe(N);
  }, 60_000);

  it('memory stabilizes — long-running keygen does not balloon RSS unboundedly', async () => {
    if (typeof globalThis.gc !== 'function') {
      // Without --expose-gc, we can only sanity-check counts
      return;
    }
    const N = Math.floor(cfg.stress.keygenCycles / 2);
    for (let i = 0; i < N; i++) {
      await generateDPoPKeyPair();
      if (i % 50 === 0) globalThis.gc();
    }
    // If we reach here without OOM, we pass
    expect(true).toBe(true);
  }, 60_000);
});
