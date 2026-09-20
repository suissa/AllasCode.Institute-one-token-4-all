import { describe, it, expect } from 'vitest';
import { generateRandomString } from '../../src/crypto/random.js';

describe('generateRandomString', () => {
  it('returns a string of expected length', () => {
    expect(generateRandomString(16)).toHaveLength(22); // 16 bytes -> 22 base64url chars
    expect(generateRandomString(32)).toHaveLength(43); // 32 bytes -> 43 base64url chars
    expect(generateRandomString(48)).toHaveLength(64); // 48 bytes -> 64 base64url chars
  });

  it('uses URL-safe alphabet and no padding', () => {
    for (let i = 0; i < 50; i++) {
      const s = generateRandomString(32);
      expect(s.includes('+')).toBe(false);
      expect(s.includes('/')).toBe(false);
      expect(s.includes('=')).toBe(false);
    }
  });

  it('produces distinct values on repeated calls', () => {
    const a = generateRandomString(32);
    const b = generateRandomString(32);
    expect(a).not.toBe(b);
  });

  it('rejects byteLength below 16', () => {
    expect(() => generateRandomString(8)).toThrow(RangeError);
  });
});
