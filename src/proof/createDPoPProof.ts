import type { CoreConfig } from '../config.js';
import { defaultConfig } from '../config.js';
import { bytesToBase64Url } from '../crypto/base64url.js';
import { exportPublicJWK } from '../crypto/keypair.js';
import { generateRandomString } from '../crypto/random.js';
import { calculateATH, calculateAuthCodeJti } from '../crypto/sha256.js';
import { sanitizeHTU } from './sanitizeHTU.js';

export interface CreateDPoPProofOptions {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  /** HTTP method. Will be uppercased before being placed in `htm`. */
  htm: string;
  /** Target URI; will be sanitized to `origin + pathname`. */
  htu: string;
  /** DPoP nonce from the AS (required after the first `use_dpop_nonce` challenge). */
  nonce?: string;
  /** When present, includes `ath` (RFC 9449 §6.1) binding to the access token. */
  accessToken?: string;
  /** When present and no explicit `jti`, jti = base64url(sha256(code)). */
  authCode?: string;
  /** Explicit jti. Wins over `authCode` and the random fallback. */
  jti?: string;
  /** Override config-driven defaults (e.g. jti random byte length). */
  config?: Readonly<CoreConfig>;
}

/**
 * Create a signed DPoP Proof JWT per RFC 9449 §4.
 *
 * Header:
 *   { "typ": "dpop+jwt", "alg": "ES256", "jwk": <public JWK> }
 *
 * Payload:
 *   { htm, htu, iat, jti } plus optional `ath` and `nonce`.
 *
 * Signature:
 *   ECDSA over SHA-256 using the private key. WebCrypto returns the raw
 *   IEEE P1363 (R||S, 64 bytes for P-256) format directly — no DER conversion.
 */
export async function createDPoPProof(opts: CreateDPoPProofOptions): Promise<string> {
  const config = opts.config ?? defaultConfig;
  const {
    privateKey,
    publicKey,
    htm,
    htu,
    nonce,
    accessToken,
    authCode,
    jti: explicitJti,
  } = opts;

  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: await exportPublicJWK(publicKey),
  };

  const jti = await resolveJti({
    ...(explicitJti !== undefined ? { explicitJti } : {}),
    ...(authCode !== undefined ? { authCode } : {}),
  }, config);

  const payload: Record<string, string | number> = {
    htm: htm.toUpperCase(),
    htu: sanitizeHTU(htu),
    iat: Math.floor(Date.now() / 1000),
    jti,
  };

  if (accessToken !== undefined) {
    payload.ath = await calculateATH(accessToken);
  }

  if (nonce !== undefined) {
    payload.nonce = nonce;
  }

  const encoder = new TextEncoder();
  const headerB64 = bytesToBase64Url(encoder.encode(JSON.stringify(header)));
  const payloadB64 = bytesToBase64Url(encoder.encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;

  const signatureBuffer = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    encoder.encode(signingInput),
  );
  const signatureB64 = bytesToBase64Url(new Uint8Array(signatureBuffer));

  return `${signingInput}.${signatureB64}`;
}

async function resolveJti(
  args: { explicitJti?: string; authCode?: string },
  config: Readonly<CoreConfig>,
): Promise<string> {
  if (args.explicitJti) return args.explicitJti;
  if (args.authCode) return calculateAuthCodeJti(args.authCode);
  return generateRandomString(config.proof.jti.randomByteLength, config);
}
