import type { CoreConfig } from '../config.js';
import { defaultConfig } from '../config.js';
import { generateDPoPKeyPair } from '../crypto/keypair.js';
import { createDPoPProof } from '../proof/createDPoPProof.js';
import type { KeyStore, StoredKey } from '../storage/KeyStore.js';
import type {
  DPoPClientOptions,
  ExchangeCodeOptions,
  RefreshOptions,
  TokenEndpointError,
  TokenEndpointResponse,
  TokenSet,
} from './types.js';

/**
 * High-level DPoP client.
 *
 * Responsibilities:
 *   - Lazily generate and persist the DPoP key pair via the configured KeyStore,
 *     OR generate-and-destroy per request when `ephemeralKeys: true` (LinearAutoDestroy).
 *   - Build and sign DPoP proofs for every token endpoint request.
 *   - Cache the AS-issued `DPoP-Nonce` and replay-with-nonce according to
 *     `config.client.nonce.maxRetries` (default 1; RFC 9449 §9).
 *   - Cache the latest successful TokenSet for downstream callers.
 *
 * LinearAutoDestroy mode (per-request ephemeral keys):
 *   When `config.client.ephemeralKeys === true`, the client generates a FRESH
 *   key pair for every token endpoint request cycle (including the nonce retry)
 *   and destroys the in-memory reference after the cycle completes. This
 *   implements the use-and-throw semantics from the UbiQ/UbiQUIC reference
 *   design.
 *
 *   ⚠ RFC 9449 §6.5 caveat: a standards-compliant AS binds the refresh token
 *   to the public key of the proof that obtained it. With ephemeral keys the
 *   public key CHANGES on every refresh, so the AS will reject subsequent
 *   refreshes with `invalid_dpop_proof`. Enable `ephemeralKeys` only for one-
 *   shot flows (client_credentials without refresh, or experimental setups
 *   against a non-RFC-strict AS).
 *
 * Not in scope:
 *   - The authorization request itself (redirect, PKCE, login UI).
 *   - Refresh-token rotation policy (caller decides; we just expose the
 *     `refresh()` method).
 */
export class DPoPClient {
  private readonly tokenEndpoint: string;
  private readonly clientId: string;
  private readonly keyStore: KeyStore;
  private readonly fetchImpl: typeof fetch;
  private readonly config: Readonly<CoreConfig>;

  private dpopNonce: string | null = null;
  private tokenSet: TokenSet | null = null;

  constructor(opts: DPoPClientOptions) {
    if (!opts.tokenEndpoint) throw new Error('DPoPClient: tokenEndpoint is required');
    if (!opts.clientId) throw new Error('DPoPClient: clientId is required');
    if (!opts.keyStore) throw new Error('DPoPClient: keyStore is required');

    this.tokenEndpoint = opts.tokenEndpoint;
    this.clientId = opts.clientId;
    this.keyStore = opts.keyStore;
    this.config = opts.config ?? defaultConfig;
    const f = opts.fetch ?? globalThis.fetch;
    if (!f) {
      throw new Error('DPoPClient: no fetch available. Pass `fetch` in options or use Node 18+.');
    }
    this.fetchImpl = f;
  }

  /** Get or create the DPoP key pair. In ephemeral mode, always generates fresh. */
  async getOrCreateKeys(): Promise<StoredKey> {
    const existing = await this.keyStore.load();
    if (existing) return existing;
    const fresh = await generateDPoPKeyPair();
    await this.keyStore.save(fresh);
    return fresh;
  }

  /** Cached AS nonce (or null if none has been seen yet). */
  getNonce(): string | null {
    return this.dpopNonce;
  }

  /** Override the cached nonce (e.g. when AS publishes one in initial headers). */
  setNonce(nonce: string | null): void {
    this.dpopNonce = nonce;
  }

  /** Most recent successful TokenSet, if any. */
  getTokenSet(): TokenSet | null {
    return this.tokenSet;
  }

  /** Forget the cached token set (but keep the key pair). */
  clearTokenSet(): void {
    this.tokenSet = null;
  }

  /**
   * Destroy the persisted key pair (LinearAutoDestroy at session boundary).
   * Idempotent. After this call, `getOrCreateKeys()` will generate a fresh pair.
   */
  async destroyKeys(): Promise<void> {
    const current = await this.keyStore.load();
    if (current) {
      await this.keyStore.destroy(current);
    }
  }

  /** Forget everything — keys and tokens. */
  async reset(): Promise<void> {
    this.tokenSet = null;
    this.dpopNonce = null;
    await this.keyStore.clear();
  }

  /** True when LinearAutoDestroy (use-and-throw) mode is active. */
  isEphemeral(): boolean {
    return this.config.client.ephemeralKeys;
  }

  /** Effective config (frozen). */
  getConfig(): Readonly<CoreConfig> {
    return this.config;
  }

  /** Exchange an authorization code for tokens. */
  async exchangeCode(opts: ExchangeCodeOptions): Promise<TokenSet> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: opts.code,
      client_id: this.clientId,
      redirect_uri: opts.redirectUri,
      code_verifier: opts.codeVerifier,
    });
    return this.tokenRequest(body, { authCode: opts.code });
  }

  /** Refresh an access token using a refresh token. */
  async refresh(opts: RefreshOptions): Promise<TokenSet> {
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: opts.refreshToken,
      client_id: this.clientId,
    });
    if (opts.scope) body.set('scope', opts.scope);
    return this.tokenRequest(body);
  }

  /**
   * Internal: POST to the token endpoint with a fresh DPoP proof, capturing
   * the DPoP-Nonce and applying the retry policy on `use_dpop_nonce`.
   *
   * In ephemeral mode (`config.client.ephemeralKeys`): the key pair is
   * generated inline, used for the entire request cycle (original + retries),
   * and destroyed via `keyStore.destroy(keys)` once the cycle finishes —
   * regardless of whether it succeeded or failed.
   */
  private async tokenRequest(
    body: URLSearchParams,
    context: { authCode?: string } = {},
    retryNonce?: string,
  ): Promise<TokenSet> {
    const ephemeral = this.config.client.ephemeralKeys;
    const keys = ephemeral
      ? await generateDPoPKeyPair()
      : await this.getOrCreateKeys();

    try {
      const effectiveNonce = retryNonce ?? this.dpopNonce;
      const proof = await createDPoPProof({
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
        htm: this.config.client.http.defaultMethod,
        htu: this.tokenEndpoint,
        ...(effectiveNonce !== undefined && effectiveNonce !== null ? { nonce: effectiveNonce } : {}),
        ...(context.authCode ? { authCode: context.authCode } : {}),
        config: this.config,
      });

      const response = await this.fetchImpl(this.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'DPoP': proof,
          'Accept': 'application/json',
        },
        body: body.toString(),
      });

      const freshNonce = response.headers.get('DPoP-Nonce');
      if (freshNonce) this.dpopNonce = freshNonce;

      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({ error: 'invalid_response' }))) as TokenEndpointError;

        const remainingRetries = this.config.client.nonce.maxRetries;
        const isNonceChallenge =
          response.status === 400 &&
          errBody.error === 'use_dpop_nonce' &&
          freshNonce !== null &&
          retryNonce === undefined &&
          remainingRetries > 0;

        if (isNonceChallenge) {
          // Single retry (or as configured) with the new nonce. Guarded by
          // `retryNonce` to prevent infinite recursion.
          return await this.tokenRequest(body, context, freshNonce);
        }

        const err = new Error(
          `Token endpoint error [${response.status}]: ${errBody.error}${
            errBody.error_description ? ' — ' + errBody.error_description : ''
          }`,
        );
        (err as Error & { body: TokenEndpointError; status: number }).body = errBody;
        (err as Error & { body: TokenEndpointError; status: number }).status = response.status;
        throw err;
      }

      const data = (await response.json()) as TokenEndpointResponse;
      const set: TokenSet = {
        accessToken: data.access_token,
        tokenType: data.token_type,
        ...(data.expires_in !== undefined ? { expiresAt: Date.now() + data.expires_in * 1000 } : {}),
        ...(data.refresh_token
          ? { refreshToken: data.refresh_token }
          : this.tokenSet?.refreshToken
            ? { refreshToken: this.tokenSet.refreshToken }
            : {}),
        ...(data.scope ? { scope: data.scope } : {}),
      };
      this.tokenSet = set;
      return set;
    } finally {
      if (ephemeral) {
        // LinearAutoDestroy: wipe references so the CryptoKeys become GC-eligible.
        await this.keyStore.destroy(keys);
      }
    }
  }
}
