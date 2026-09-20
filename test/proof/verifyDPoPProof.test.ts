import { describe, it, expect } from 'vitest';
import { verifyDPoPProof } from '../../src/proof/verifyDPoPProof.js';
import { createDPoPProof } from '../../src/proof/createDPoPProof.js';
import { generateDPoPKeyPair } from '../../src/crypto/keypair.js';
import { bytesToBase64Url, base64UrlToBytes } from '../../src/crypto/base64url.js';

describe('verifyDPoPProof', () => {
  it('accepts a freshly minted valid proof', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://example.com/token',
    });
    const result = await verifyDPoPProof(proof);
    expect(result.isValid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('rejects a JWT with wrong number of segments', async () => {
    const r = await verifyDPoPProof('a.b');
    expect(r.isValid).toBe(false);
    expect(r.error).toMatch(/3 segments/);
  });

  it('rejects when signature is tampered', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://example.com/token',
    });
    const parts = proof.split('.');
    // Flip a byte in the signature
    const tampered = parts[0] + '.' + parts[1] + '.' + 'AAAA' + parts[2]!.slice(4);
    const r = await verifyDPoPProof(tampered);
    expect(r.isValid).toBe(false);
    expect(r.error).toMatch(/Invalid signature/);
  });

  it('rejects when payload is tampered (signature no longer matches)', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://example.com/token',
    });
    const parts = proof.split('.');
    // Swap payload to a different value (we cannot sign it, so verify should fail)
    const evilPayload = bytesToBase64Url(new TextEncoder().encode(JSON.stringify({ htm: 'GET', htu: 'https://evil', iat: 0, jti: 'x' })));
    const tampered = `${parts[0]}.${evilPayload}.${parts[2]}`;
    const r = await verifyDPoPProof(tampered);
    expect(r.isValid).toBe(false);
  });

  it('rejects when header typ is wrong', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://example.com/token',
    });
    const parts = proof.split('.');
    const originalHeader = JSON.parse(new TextDecoder().decode(base64UrlToBytes(parts[0]!))) as Record<string, unknown>;
    const tamperedHeader = bytesToBase64Url(new TextEncoder().encode(JSON.stringify({
      typ: 'JWT',
      alg: 'ES256',
      jwk: originalHeader.jwk,
    })));
    const tampered = `${tamperedHeader}.${parts[1]}.${parts[2]}`;
    const r = await verifyDPoPProof(tampered);
    expect(r.isValid).toBe(false);
    expect(r.error).toMatch(/Invalid typ/);
  });

  it('rejects when header alg is wrong', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://example.com/token',
    });
    const parts = proof.split('.');
    const originalHeader = JSON.parse(new TextDecoder().decode(base64UrlToBytes(parts[0]!))) as Record<string, unknown>;
    const tamperedHeader = bytesToBase64Url(new TextEncoder().encode(JSON.stringify({
      ...originalHeader,
      alg: 'HS256',
    })));
    const tampered = `${tamperedHeader}.${parts[1]}.${parts[2]}`;
    const r = await verifyDPoPProof(tampered);
    expect(r.isValid).toBe(false);
    expect(r.error).toMatch(/Invalid alg/);
  });

  it('rejects malformed base64', async () => {
    const r = await verifyDPoPProof('!!!.!!!.!!!');
    expect(r.isValid).toBe(false);
  });
});
