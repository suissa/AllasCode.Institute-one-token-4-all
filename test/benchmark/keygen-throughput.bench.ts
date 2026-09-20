import { describe, it, expect } from 'vitest';
import { Bench } from 'tinybench';
import { generateDPoPKeyPair, exportPublicJWK } from '../../src/crypto/keypair.js';
import { createDPoPProof } from '../../src/proof/createDPoPProof.js';
import { verifyDPoPProof } from '../../src/proof/verifyDPoPProof.js';
import { generateRandomString } from '../../src/crypto/random.js';
import { generatePKCE } from '../../src/crypto/pkce.js';
import { loadConfig } from '../../src/config.js';

/**
 * Benchmark suite — runs tinybench against the hot paths and reports
 * ops/sec and avg latency. Does not assert pass/fail thresholds; the
 * numbers are useful for regression tracking.
 *
 * Run with: `npx vitest run test/benchmark/`
 */

const cfg = loadConfig();

describe('Benchmark: hot path throughput', () => {
  it('runs the full benchmark suite and logs the table', async () => {
    const bench = new Bench({ time: 1000 });

    bench
      .add('generateDPoPKeyPair', () => generateDPoPKeyPair())
      .add('generateRandomString(32)', () => generateRandomString(32))
      .add('generatePKCE', () => generatePKCE(cfg));

    // Setup a key pair for the proof/verify benchmarks
    const kp = await generateDPoPKeyPair();
    bench
      .add('exportPublicJWK', () => exportPublicJWK(kp.publicKey))
      .add('createDPoPProof', () =>
        createDPoPProof({
          publicKey: kp.publicKey,
          privateKey: kp.privateKey,
          htm: 'POST',
          htu: 'https://as.example.com/token',
        }),
      );

    // Setup a proof for verify
    const proof = await createDPoPProof({
      publicKey: kp.publicKey,
      privateKey: kp.privateKey,
      htm: 'POST',
      htu: 'https://as.example.com/token',
    });
    bench.add('verifyDPoPProof', () => verifyDPoPProof(proof));

    await bench.run();

    // Print the raw table from tinybench (it has the canonical columns).
    // eslint-disable-next-line no-console
    console.log('\n=== one-token-4-all benchmark (tinybench) ===');
    // eslint-disable-next-line no-console
    console.table(bench.table());

    // Sanity assertion: every benchmark completed at least 1 task
    const results = bench.table();
    expect(results.length).toBeGreaterThanOrEqual(6);
  }, 30_000);
});
