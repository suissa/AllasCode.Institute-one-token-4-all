/** A pair of CryptoKeys persisted by a KeyStore. */
export interface StoredKey {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/**
 * Pluggable persistence for DPoP key pairs.
 *
 * Implementations:
 *   - MemoryKeyStore — process-lifetime, useful for tests and short-lived BFFs.
 *   - IndexedDBKeyStore — browser-only, can hold CryptoKeys directly.
 *   - NodeKeyStore — wraps the key JWK with a master key from env / KMS.
 *   - WebAuthnKeyStore — PRF extension of a passkey (future).
 *
 * Note: the private key passed to `save` MUST be non-extractable
 * (`extractable === false`). The interface does not enforce this; callers
 * that build CryptoKeys via `generateDPoPKeyPair` already get this property.
 *
 * LinearAutoDestroy:
 *   `destroy(key)` removes the store's reference to a key pair so that the
 *   underlying CryptoKey objects become eligible for GC. This is the
 *   use-and-throw seam invoked by DPoPClient in `ephemeralKeys` mode and at
 *   session boundaries.
 */
export interface KeyStore {
  /** Returns the stored key pair or null if there is none / it has been destroyed. */
  load(): Promise<StoredKey | null>;
  /** Persist a key pair, replacing any existing entry. */
  save(key: StoredKey): Promise<void>;
  /**
   * Destroy a specific key pair reference. Idempotent: destroying twice is a
   * no-op. The store will return null from `load()` until `save()` is called
   * again. Does NOT free the WebCrypto material (the spec offers no API for
   * that); it only removes the JS reference.
   */
  destroy(key: StoredKey): Promise<void>;
  /** Forget the stored key pair (logout / reset). */
  clear(): Promise<void>;
}
