import { describe, it, expect } from 'vitest';
import { generatePKCE } from '../../src/crypto/pkce.js';
import { sha256 } from '../../src/crypto/sha256.js';
import { bytesToBase64Url } from '../../src/crypto/base64url.js';

describe('generatePKCE', () => {
  it('verifier is 43 chars (32 bytes -> base64url without padding)', async () => {
    const { codeVerifier } = await generatePKCE();
    expect(codeVerifier).toHaveLength(43);
  });

  it('challenge equals base64url(sha256(verifier))', async () => {
    const { codeVerifier, codeChallenge } = await generatePKCE();
    const expected = bytesToBase64Url(await sha256(codeVerifier));
    expect(codeChallenge).toBe(expected);
  });

  it('uses S256 method', async () => {
    const { codeChallengeMethod } = await generatePKCE();
    expect(codeChallengeMethod).toBe('S256');
  });

  it('produces distinct values on repeated calls', async () => {
    const a = await generatePKCE();
    const b = await generatePKCE();
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
    expect(a.codeChallenge).not.toBe(b.codeChallenge);
  });
});
