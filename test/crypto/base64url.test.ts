import { describe, it, expect } from 'vitest';
import {
  bytesToBase64Url,
  base64UrlToBytes,
  stringToBase64Url,
  base64UrlToString,
  base64UrlEncode,
  base64UrlDecode,
} from '../../src/crypto/base64url.js';

describe('base64url', () => {
  const fixture = new Uint8Array([0x00, 0x01, 0x02, 0xfe, 0xff]);

  it('round-trips bytes', () => {
    const encoded = bytesToBase64Url(fixture);
    const decoded = base64UrlToBytes(encoded);
    expect(Array.from(decoded)).toEqual(Array.from(fixture));
  });

  it('uses URL-safe alphabet (no + / or = padding)', () => {
    // 0xfbff -> +/8 which contains + and / under standard base64
    const tricky = new Uint8Array([0xfb, 0xff, 0xff, 0xff]);
    const out = bytesToBase64Url(tricky);
    expect(out.includes('+')).toBe(false);
    expect(out.includes('/')).toBe(false);
    expect(out.includes('=')).toBe(false);
  });

  it('round-trips UTF-8 strings', () => {
    const s = 'olá, mundo 🌍 — ção';
    expect(base64UrlToString(stringToBase64Url(s))).toBe(s);
  });

  it('base64UrlEncode accepts ArrayBuffer', () => {
    const ab = new Uint8Array([1, 2, 3]).buffer;
    expect(base64UrlEncode(ab)).toBe(bytesToBase64Url(new Uint8Array(ab)));
  });

  it('base64UrlEncode accepts Uint8Array', () => {
    const out = base64UrlEncode(fixture);
    expect(out).toBe(bytesToBase64Url(fixture));
  });

  it('base64UrlDecode mirrors base64UrlEncode', () => {
    const arr = base64UrlDecode(bytesToBase64Url(fixture));
    expect(Array.from(arr)).toEqual(Array.from(fixture));
  });
});
