/** A DPoP key pair: ECDSA P-256 with a non-extractable private key. */
export interface DPoPKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/** Public JWK in the exact shape required by RFC 9449 DPoP proofs. */
export interface PublicJWK {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}

/**
 * Generate a DPoP key pair (ECDSA P-256).
 *
 * Security guardrails:
 * - Public key is `extractable: true` so it can be embedded as a JWK in the
 *   DPoP proof header.
 * - Private key is `extractable: false` — it can never leave the WebCrypto
 *   boundary (hardware keystore on supported platforms, JS sandbox memory
 *   otherwise). Thwarts XSS-based key exfiltration.
 *
 * `crypto.subtle.generateKey` only accepts a single `extractable` flag for the
 * whole pair, so we generate as extractable, export the JWKs, then re-import
 * the private key with `extractable: false`. The exported JWKs are scoped to
 * this function and become garbage.
 */
export async function generateDPoPKeyPair(): Promise<DPoPKeyPair> {
  const generated = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    /* extractable */ true,
    ['sign', 'verify'],
  );

  const publicJwk = await crypto.subtle.exportKey('jwk', generated.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', generated.privateKey);

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    publicJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    /* extractable */ true,
    ['verify'],
  );

  const privateKey = await crypto.subtle.importKey(
    'jwk',
    privateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    /* extractable */ false,
    ['sign'],
  );

  return { publicKey, privateKey };
}

/**
 * Export a public CryptoKey as a DPoP-compliant JWK.
 * Strips private fields and WebCrypto metadata; returns only kty/crv/x/y.
 */
export async function exportPublicJWK(publicKey: CryptoKey): Promise<PublicJWK> {
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    throw new Error('exportPublicJWK: key is not a P-256 EC public key');
  }
  return {
    kty: 'EC',
    crv: 'P-256',
    x: jwk.x,
    y: jwk.y,
  };
}
