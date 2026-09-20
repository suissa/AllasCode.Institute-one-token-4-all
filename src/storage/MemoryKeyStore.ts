import type { KeyStore, StoredKey } from './KeyStore.js';

/**
 * Process-lifetime in-memory KeyStore.
 *
 * - `destroy(key)` records both CryptoKeys in a destroyed set and clears the
 *   stored reference if it matches the passed key. Subsequent `load()` returns
 *   null until `save()` is called again.
 * - `clear()` is equivalent to destroying the currently-stored pair.
 *
 * Intended for:
 *   - unit tests
 *   - short-lived Backend-for-Frontend processes
 *   - DPoPClient in `ephemeralKeys` (LinearAutoDestroy) mode
 */
export class MemoryKeyStore implements KeyStore {
  private keys: StoredKey | null = null;
  private readonly destroyed = new WeakSet<CryptoKey>();

  async load(): Promise<StoredKey | null> {
    if (this.keys && this.isDestroyed(this.keys)) {
      this.keys = null;
    }
    return this.keys;
  }

  async save(key: StoredKey): Promise<void> {
    this.keys = key;
    this.destroyed.delete(key.privateKey);
    this.destroyed.delete(key.publicKey);
  }

  async destroy(key: StoredKey): Promise<void> {
    this.destroyed.add(key.privateKey);
    this.destroyed.add(key.publicKey);
    if (this.keys === key) {
      this.keys = null;
    }
  }

  async clear(): Promise<void> {
    if (this.keys) {
      this.destroyed.add(this.keys.privateKey);
      this.destroyed.add(this.keys.publicKey);
    }
    this.keys = null;
  }

  /** Test/observability helper: has this specific key been destroyed? */
  isDestroyed(key: StoredKey): boolean {
    return this.destroyed.has(key.privateKey) || this.destroyed.has(key.publicKey);
  }
}
