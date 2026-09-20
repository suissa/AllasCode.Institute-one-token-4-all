import { base64UrlToBytes } from '../crypto/base64url.js';

export interface VerifyDPoPProofResult {
  isValid: boolean;
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
  error?: string;
}

/**
 * Verify a DPoP Proof JWT.
 *
 * Checks (in order):
 *   1. Three base64url segments.
 *   2. header.typ == "dpop+jwt" and header.alg == "ES256".
 *   3. header.jwk present and parseable as P-256 EC public key.
 *   4. ECDSA signature over SHA-256 verifies with that public key.
 *
 * Does NOT verify:
 *   - `htm`/`htu` match a specific request (caller's responsibility).
 *   - `iat` freshness (caller decides window; DPoP proofs are short-lived).
 *   - `nonce` binding (caller compares to the AS-issued nonce).
 *   - `ath` matches a specific access token (caller compares).
 */
export async function verifyDPoPProof(jwt: string): Promise<VerifyDPoPProofResult> {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    return { isValid: false, error: 'DPoP proof must have exactly 3 segments' };
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  if (!headerB64 || !payloadB64 || !signatureB64) {
    return { isValid: false, error: 'DPoP proof has empty segment' };
  }

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(headerB64))) as Record<string, unknown>;
    payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadB64))) as Record<string, unknown>;
  } catch (err) {
    return { isValid: false, error: `Malformed base64url/JSON: ${(err as Error).message}` };
  }

  if (header['typ'] !== 'dpop+jwt') {
    return { isValid: false, header, payload, error: `Invalid typ: ${String(header['typ'])}` };
  }
  if (header['alg'] !== 'ES256') {
    return { isValid: false, header, payload, error: `Invalid alg: ${String(header['alg'])}` };
  }
  const jwk = header['jwk'];
  if (!jwk || typeof jwk !== 'object') {
    return { isValid: false, header, payload, error: 'Missing jwk in header' };
  }

  let publicKey: CryptoKey;
  try {
    publicKey = await crypto.subtle.importKey(
      'jwk',
      jwk as JsonWebKey,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    );
  } catch (err) {
    return { isValid: false, header, payload, error: `Invalid jwk: ${(err as Error).message}` };
  }

  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = base64UrlToBytes(signatureB64);

  let signatureValid = false;
  try {
    signatureValid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      signature.slice(),
      new TextEncoder().encode(signingInput),
    );
  } catch (err) {
    return { isValid: false, header, payload, error: `Signature verify threw: ${(err as Error).message}` };
  }

  if (!signatureValid) {
    return { isValid: false, header, payload, error: 'Invalid signature' };
  }

  return { isValid: true, header, payload };
}
