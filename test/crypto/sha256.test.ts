import { describe, it, expect } from 'vitest';
import { sha256, calculateATH, calculateAuthCodeJti } from '../../src/crypto/sha256.js';
import { base64UrlToBytes } from '../../src/crypto/base64url.js';

describe('sha256', () => {
  it('matches the SHA-256 of empty string', async () => {
    const out = await sha256('');
    // Known: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    expect(Array.from(out)).toEqual([
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
      0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
      0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    ]);
  });

  it('matches the SHA-256 of "abc"', async () => {
    const out = await sha256('abc');
    // Known: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    expect(Array.from(out).slice(0, 4)).toEqual([0xba, 0x78, 0x16, 0xbf]);
  });

  it('calculateATH is base64url(sha256(token)) with no padding', async () => {
    const token = 'access-token-value';
    const ath = await calculateATH(token);
    expect(ath.includes('=')).toBe(false);
    const decoded = base64UrlToBytes(ath);
    expect(decoded.length).toBe(32);
  });

  it('calculateAuthCodeJti is deterministic for the same code', async () => {
    const a = await calculateAuthCodeJti('the-code');
    const b = await calculateAuthCodeJti('the-code');
    expect(a).toBe(b);
    const c = await calculateAuthCodeJti('the-code-2');
    expect(a).not.toBe(c);
    expect(a.includes('=')).toBe(false);
  });
});
