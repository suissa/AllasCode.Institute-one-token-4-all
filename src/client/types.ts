import type { CoreConfig } from '../config.js';
import type { KeyStore } from '../storage/KeyStore.js';

/** Successful token set returned by the AS, in client-friendly shape. */
export interface TokenSet {
  accessToken: string;
  tokenType: string;
  expiresAt?: number;
  refreshToken?: string;
  scope?: string;
}

/** Subset of RFC 6749 §5.1 we care about. */
export interface TokenEndpointResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

/** RFC 6749 §5.2 error response, extended with RFC 9449 `use_dpop_nonce`. */
export interface TokenEndpointError {
  error: string;
  error_description?: string;
  error_uri?: string;
}

export interface DPoPClientOptions {
  /** Token endpoint URL, e.g. `https://oauth2.googleapis.com/token`. */
  tokenEndpoint: string;
  /** OAuth client_id registered with the AS. */
  clientId: string;
  /** Where to persist the DPoP key pair between requests. */
  keyStore: KeyStore;
  /** Optional fetch override (for testing). Defaults to globalThis.fetch. */
  fetch?: typeof fetch;
  /**
   * Override runtime tunables (nonce retries, HTTP timeouts, ephemeral mode).
   * Defaults to `defaultConfig` from `src/config.ts`. Protocol-mandated values
   * (P-256, ES256, dpop+jwt, ATH) are NOT taken from here — they are enforced
   * by the loader's literal types.
   */
  config?: CoreConfig;
}

export interface ExchangeCodeOptions {
  code: string;
  codeVerifier: string;
  redirectUri: string;
}

export interface RefreshOptions {
  refreshToken: string;
  scope?: string;
}
