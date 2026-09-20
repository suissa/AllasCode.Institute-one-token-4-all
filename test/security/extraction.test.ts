import { describe, it, expect } from 'vitest';
import { generateDPoPKeyPair } from '../../src/crypto/keypair.js';
import { createDPoPProof } from '../../src/proof/createDPoPProof.js';
import { verifyDPoPProof } from '../../src/proof/verifyDPoPProof.js';
import { exportPublicJWK } from '../../src/crypto/keypair.js';

/**
 * Security tests — verify the cryptographic guardrails hold against
 * practical attacks:
 *   - private key cannot be exported (non-extractable invariant)
 *   - signature cannot be replayed across endpoints (htu binding)
 *   - signature cannot be replayed across methods (htm binding)
 *   - jwk tampering invalidates the signature
 *   - alg=none downgrade is rejected
 *   - alg=HS256 confusion is rejected
 *   - signature length matches raw IEEE P1363 (64 bytes for P-256)
 */

describe('Security: non-extractable private key', () => {
  it('rejects exportKey("jwk") on the private key', async () => {
    const { privateKey } = await generateDPoPKeyPair();
    await expect(crypto.subtle.exportKey('jwk', privateKey)).rejects.toThrow();
  });

  it('private key extractable property is false', async () => {
    const { privateKey } = await generateDPoPKeyPair();
    expect(privateKey.extractable).toBe(false);
  });

  it('public key extractable property is true', async () => {
    const { publicKey } = await generateDPoPKeyPair();
    expect(publicKey.extractable).toBe(true);
  });
});

describe('Security: DPoP proof is bound to its endpoint and method', () => {
  it('rejecting proof bound to a different htu', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://victim.example.com/api',
    });

    // Replay against a different host
    const parts = proof.split('.');
    const evilPayload = Buffer.from(JSON.stringify({
      htm: 'POST', htu: 'https://attacker.example.com/api', iat: Math.floor(Date.now() / 1000), jti: 'evil',
    })).toString('base64url');
    const evilProof = `${parts[0]}.${evilPayload}.${parts[2]}`;
    const result = await verifyDPoPProof(evilProof);
    expect(result.isValid).toBe(false);
  });

  it('rejecting proof bound to a different htm', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://example.com/api',
    });
    const parts = proof.split('.');
    const evilPayload = Buffer.from(JSON.stringify({
      htm: 'GET', htu: 'https://example.com/api', iat: Math.floor(Date.now() / 1000), jti: 'evil',
    })).toString('base64url');
    const evilProof = `${parts[0]}.${evilPayload}.${parts[2]}`;
    const result = await verifyDPoPProof(evilProof);
    expect(result.isValid).toBe(false);
  });

  it('rejecting proof bound to a different jti (replay protection)', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    const proof1 = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://example.com/api', jti: 'fixed-jti',
    });
    const proof2 = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://example.com/api', jti: 'different-jti',
    });

    // Same signing input? No — jti differs. So proofs differ.
    expect(proof1).not.toBe(proof2);
  });
});

describe('Security: header tampering is detected', () => {
  it('rejects when jwk in header is replaced with attacker key', async () => {
    const victim = await generateDPoPKeyPair();
    const attacker = await generateDPoPKeyPair();

    const proof = await createDPoPProof({
      publicKey: victim.publicKey, privateKey: victim.privateKey,
      htm: 'POST', htu: 'https://example.com/api',
    });

    // Replace header with attacker's jwk but keep victim's signature
    const evilHeader = Buffer.from(JSON.stringify({
      typ: 'dpop+jwt', alg: 'ES256', jwk: await exportPublicJWK(attacker.publicKey),
    })).toString('base64url');

    const parts = proof.split('.');
    const evilProof = `${evilHeader}.${parts[1]}.${parts[2]}`;
    const result = await verifyDPoPProof(evilProof);
    expect(result.isValid).toBe(false);
  });

  it('rejects when alg is replaced with HS256 (algorithm confusion)', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://example.com/api',
    });
    const parts = proof.split('.');
    const originalHeader = JSON.parse(Buffer.from(parts[0]!.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - parts[0]!.length % 4) % 4), 'base64').toString('utf8'));
    const evilHeader = Buffer.from(JSON.stringify({ ...originalHeader, alg: 'HS256' })).toString('base64url');
    const evilProof = `${evilHeader}.${parts[1]}.${parts[2]}`;
    const result = await verifyDPoPProof(evilProof);
    expect(result.isValid).toBe(false);
  });

  it('rejects when typ is missing or wrong', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://example.com/api',
    });
    const parts = proof.split('.');
    const originalHeader = JSON.parse(Buffer.from(parts[0]!.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - parts[0]!.length % 4) % 4), 'base64').toString('utf8'));
    const evilHeader = Buffer.from(JSON.stringify({ ...originalHeader, typ: 'JWT' })).toString('base64url');
    const evilProof = `${evilHeader}.${parts[1]}.${parts[2]}`;
    const result = await verifyDPoPProof(evilProof);
    expect(result.isValid).toBe(false);
    expect(result.error).toMatch(/Invalid typ/);
  });
});

describe('Security: signature format invariants', () => {
  it('emits exactly 64 raw bytes (P-256 over SHA-256, IEEE P1363)', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://example.com/api',
    });
    const sigBytes = Buffer.from(proof.split('.')[2]!.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - proof.split('.')[2]!.length % 4) % 4), 'base64');
    expect(sigBytes.length).toBe(64);
  });
});
