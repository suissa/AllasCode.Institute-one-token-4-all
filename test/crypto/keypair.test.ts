import { describe, it, expect } from 'vitest';
import { generateDPoPKeyPair, exportPublicJWK } from '../../src/crypto/keypair.js';

describe('generateDPoPKeyPair', () => {
  it('returns a CryptoKey pair usable for sign/verify', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    expect(publicKey.algorithm.name).toBe('ECDSA');
    // P-256 has namedCurve inside algorithm
    expect((publicKey.algorithm as EcKeyGenParams).namedCurve).toBe('P-256');
    expect(privateKey.algorithm.name).toBe('ECDSA');
    expect((privateKey.algorithm as EcKeyGenParams).namedCurve).toBe('P-256');
  });

  it('public key is extractable, private key is NOT extractable', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    expect(publicKey.extractable).toBe(true);
    expect(privateKey.extractable).toBe(false);
  });

  it('can actually sign and verify', async () => {
    const { publicKey, privateKey } = await generateDPoPKeyPair();
    const data = new TextEncoder().encode('hello');
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      data,
    );
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sig,
      data,
    );
    expect(ok).toBe(true);
  });

  it('private key cannot be exported as JWK', async () => {
    const { privateKey } = await generateDPoPKeyPair();
    await expect(crypto.subtle.exportKey('jwk', privateKey)).rejects.toBeDefined();
  });
});

describe('exportPublicJWK', () => {
  it('returns only kty/crv/x/y in the strict shape', async () => {
    const { publicKey } = await generateDPoPKeyPair();
    const jwk = await exportPublicJWK(publicKey);
    expect(jwk).toEqual({
      kty: 'EC',
      crv: 'P-256',
      x: expect.any(String),
      y: expect.any(String),
    });
    expect(Object.keys(jwk).sort()).toEqual(['crv', 'kty', 'x', 'y']);
  });

  it('x and y are base64url-encoded 32-byte coordinates', async () => {
    const { publicKey } = await generateDPoPKeyPair();
    const jwk = await exportPublicJWK(publicKey);
    expect(jwk.x).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(jwk.y).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(jwk.x.includes('=')).toBe(false);
    expect(jwk.y.includes('=')).toBe(false);
  });
});
