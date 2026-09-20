import type { CoreConfig } from '../config.js';
import { defaultConfig } from '../config.js';
import { bytesToBase64Url } from './base64url.js';
import { sha256 } from './sha256.js';

export interface PKCEPair {
  /** 43-128 base64url chars (RFC 7636 §4.1). Configurable via `crypto.pkce.verifierByteLength`. */
  codeVerifier: string;
  /** base64url(SHA-256(verifier)). */
  codeChallenge: string;
  codeChallengeMethod: 'S256';
}

/**
 * Generate a PKCE pair per RFC 7636.
 * - code_verifier: random bytes from `config.crypto.pkce.verifierByteLength` -> base64url chars (no padding)
 * - code_challenge: base64url(SHA-256(verifier))
 */
export async function generatePKCE(config: Readonly<CoreConfig> = defaultConfig): Promise<PKCEPair> {
  const verifierBytes = new Uint8Array(config.crypto.pkce.verifierByteLength);
  crypto.getRandomValues(verifierBytes);
  const codeVerifier = bytesToBase64Url(verifierBytes);

  const challengeHash = await sha256(codeVerifier);
  const codeChallenge = bytesToBase64Url(challengeHash);

  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256',
  };
}
