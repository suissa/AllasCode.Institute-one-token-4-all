import { describe, it, expect } from 'vitest';
import { generateDPoPKeyPair } from '../../src/crypto/keypair.js';
import { createDPoPProof } from '../../src/proof/createDPoPProof.js';
import { verifyDPoPProof } from '../../src/proof/verifyDPoPProof.js';
import { loadConfig } from '../../src/config.js';

/**
 * Load test — generate many proofs concurrently and verify all succeed.
 *
 * Parallelism is configured via `load.parallelProofs` in core.yml.
 */

const cfg = loadConfig();

describe(`Load: ${cfg.load.parallelProofs} concurrent DPoP proofs`, () => {
  it(`generates, signs, and verifies ${cfg.load.parallelProofs} proofs in parallel`, async () => {
    const N = cfg.load.parallelProofs;

    // Pre-generate N key pairs
    const keyPairs = await Promise.all(Array.from({ length: N }, () => generateDPoPKeyPair()));

    const t0 = performance.now();
    const proofs = await Promise.all(
      keyPairs.map((kp, i) =>
        createDPoPProof({
          publicKey: kp.publicKey,
          privateKey: kp.privateKey,
          htm: 'POST',
          htu: 'https://as.example.com/token',
          jti: `parallel-${i}`,
        }),
      ),
    );
    const tGen = performance.now() - t0;

    expect(proofs).toHaveLength(N);
    // Every proof is structurally a 3-segment JWT
    for (const p of proofs) {
      expect(p.split('.')).toHaveLength(3);
    }

    const t1 = performance.now();
    const results = await Promise.all(proofs.map((p) => verifyDPoPProof(p)));
    const tVerify = performance.now() - t1;

    expect(results.every((r) => r.isValid)).toBe(true);
    // Loose sanity: should complete under 5s on any modern machine
    expect(tGen).toBeLessThan(5_000);
    expect(tVerify).toBeLessThan(5_000);
  });

  it(`each proof uses a distinct jti even under contention`, async () => {
    const N = cfg.load.parallelProofs;
    const keyPairs = await Promise.all(Array.from({ length: N }, () => generateDPoPKeyPair()));
    const proofs = await Promise.all(
      keyPairs.map((kp) =>
        createDPoPProof({
          publicKey: kp.publicKey,
          privateKey: kp.privateKey,
          htm: 'POST',
          htu: 'https://as.example.com/api',
        }),
      ),
    );
    const jtis = proofs.map((p) => JSON.parse(Buffer.from(p.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - p.split('.')[1]!.length % 4) % 4), 'base64').toString('utf8')).jti);
    expect(new Set(jtis).size).toBe(N); // all unique
  });
});
