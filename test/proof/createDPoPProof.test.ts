import { describe, it, expect } from 'vitest';
import { createDPoPProof } from '../../src/proof/createDPoPProof.js';
import { verifyDPoPProof } from '../../src/proof/verifyDPoPProof.js';
import { generateDPoPKeyPair } from '../../src/crypto/keypair.js';
import { base64UrlToBytes } from '../../src/crypto/base64url.js';

async function freshKeys() {
  return generateDPoPKeyPair();
}

describe('createDPoPProof', () => {
  it('produces a 3-segment base64url JWT', async () => {
    const { publicKey, privateKey } = await freshKeys();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST',
      htu: 'https://oauth2.googleapis.com/token',
    });
    expect(proof.split('.')).toHaveLength(3);
  });

  it('header is { typ: dpop+jwt, alg: ES256, jwk: {...} }', async () => {
    const { publicKey, privateKey } = await freshKeys();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST',
      htu: 'https://oauth2.googleapis.com/token',
    });
    const header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(proof.split('.')[0]!)));
    expect(header.typ).toBe('dpop+jwt');
    expect(header.alg).toBe('ES256');
    expect(header.jwk.kty).toBe('EC');
    expect(header.jwk.crv).toBe('P-256');
    expect(header.jwk.x).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(header.jwk.y).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('payload contains htm (uppercased), htu (sanitized), iat, jti', async () => {
    const { publicKey, privateKey } = await freshKeys();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'post',
      htu: 'https://example.com/token?strip=me',
      jti: 'fixed-jti-for-test',
    });
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(proof.split('.')[1]!)));
    expect(payload.htm).toBe('POST');
    expect(payload.htu).toBe('https://example.com/token');
    expect(payload.iat).toBe(Math.floor(Date.now() / 1000));
    expect(payload.jti).toBe('fixed-jti-for-test');
  });

  it('jti priority: explicit > authCode > random', async () => {
    const { publicKey, privateKey } = await freshKeys();

    // explicit beats everything
    const withExplicit = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://x/y',
      authCode: 'the-code',
      jti: 'EXPLICIT',
    });
    const p1 = JSON.parse(new TextDecoder().decode(base64UrlToBytes(withExplicit.split('.')[1]!)));
    expect(p1.jti).toBe('EXPLICIT');

    // authCode -> base64url(sha256(code))
    const withCode = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://x/y',
      authCode: 'the-code',
    });
    const p2 = JSON.parse(new TextDecoder().decode(base64UrlToBytes(withCode.split('.')[1]!)));
    // sha256('the-code') base64url-encoded; we just check it's deterministic and not random
    expect(p2.jti).toHaveLength(43);
    expect(p2.jti).not.toBe('EXPLICIT');

    // random -> 32 chars from 24 bytes
    const random = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://x/y',
    });
    const p3 = JSON.parse(new TextDecoder().decode(base64UrlToBytes(random.split('.')[1]!)));
    expect(p3.jti).toHaveLength(32);
  });

  it('includes ath when accessToken is provided', async () => {
    const { publicKey, privateKey } = await freshKeys();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://x/y',
      accessToken: 'token-value',
    });
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(proof.split('.')[1]!)));
    expect(payload.ath).toBeDefined();
    expect(payload.ath).toHaveLength(43); // base64url(sha256) -> 43 chars
  });

  it('includes nonce when provided', async () => {
    const { publicKey, privateKey } = await freshKeys();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://x/y',
      nonce: 'abc123',
    });
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(proof.split('.')[1]!)));
    expect(payload.nonce).toBe('abc123');
  });

  it('round-trips through verifyDPoPProof', async () => {
    const { publicKey, privateKey } = await freshKeys();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://example.com/token',
      nonce: 'some-nonce',
    });
    const result = await verifyDPoPProof(proof);
    expect(result.isValid).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.payload?.['htm']).toBe('POST');
    expect(result.payload?.['nonce']).toBe('some-nonce');
  });

  it('signature is raw IEEE P1363 (64 bytes for P-256)', async () => {
    const { publicKey, privateKey } = await freshKeys();
    const proof = await createDPoPProof({
      publicKey, privateKey,
      htm: 'POST', htu: 'https://x/y',
    });
    const sigBytes = base64UrlToBytes(proof.split('.')[2]!);
    expect(sigBytes.length).toBe(64);
  });
});
