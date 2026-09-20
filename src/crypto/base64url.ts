/**
 * Base64URL encoding/decoding per RFC 7515 §2.
 * - URL-safe alphabet: '-' instead of '+', '_' instead of '/'
 * - No trailing '=' padding
 *
 * Works in Node 18+ (globalThis.btoa/atob) and modern browsers.
 */

/** Encode a byte sequence to a base64url string (no padding). */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  const b64 = btoa(binary);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decode a base64url string back to bytes. Restores padding and standard alphabet. */
export function base64UrlToBytes(s: string): Uint8Array {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) {
    b64 += '=';
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** UTF-8 encode a string, then base64url-encode the bytes. */
export function stringToBase64Url(str: string): string {
  const bytes = new TextEncoder().encode(str);
  return bytesToBase64Url(bytes);
}

/** Decode a base64url string to a UTF-8 string. */
export function base64UrlToString(s: string): string {
  const bytes = base64UrlToBytes(s);
  return new TextDecoder().decode(bytes);
}

/** Alias matching the dpop-adoption skill signature: ArrayBuffer | Uint8Array -> base64url string. */
export function base64UrlEncode(buffer: Uint8Array | ArrayBuffer): string {
  if (buffer instanceof ArrayBuffer) {
    return bytesToBase64Url(new Uint8Array(buffer));
  }
  return bytesToBase64Url(buffer);
}

/** Alias matching the dpop-adoption skill signature: base64url string -> Uint8Array. */
export function base64UrlDecode(str: string): Uint8Array {
  return base64UrlToBytes(str);
}
