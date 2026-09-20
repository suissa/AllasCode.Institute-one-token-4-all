import { bytesToBase64Url } from './base64url.js';

/** SHA-256 of a string or byte sequence. Returns 32 bytes. */
export async function sha256(input: Uint8Array | string): Promise<Uint8Array> {
  const data = typeof input === 'string'
    ? new TextEncoder().encode(input)
    : input;
  // .slice() copies into a fresh ArrayBuffer, sidestepping the
  // SharedArrayBuffer narrowing that TS 5.7+ applies to BufferSource.
  const hash = await crypto.subtle.digest('SHA-256', data.slice());
  return new Uint8Array(hash);
}

/**
 * RFC 9449 §6.1: ath = base64url(SHA-256(access_token)).
 * Proves possession of the access token in DPoP-bound resource requests.
 */
export async function calculateATH(accessToken: string): Promise<string> {
  return bytesToBase64Url(await sha256(accessToken));
}

/**
 * Cryptographically bind a DPoP proof to an authorization code.
 * jti = base64url(SHA-256(code)) so that the same proof cannot be replayed
 * with a different code.
 */
export async function calculateAuthCodeJti(code: string): Promise<string> {
  return bytesToBase64Url(await sha256(code));
}
