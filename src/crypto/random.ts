import type { CoreConfig } from '../config.js';
import { defaultConfig } from '../config.js';
import { bytesToBase64Url } from './base64url.js';

/**
 * Cryptographically random base64url string (no padding).
 * Default byte length and minimum entropy floor come from `config.crypto.random`.
 * Pass a `config` override to tune without touching YAML.
 */
export function generateRandomString(
  byteLength?: number,
  config: Readonly<CoreConfig> = defaultConfig,
): string {
  const n = byteLength ?? config.crypto.random.defaultByteLength;
  if (n < config.crypto.random.minByteLength) {
    throw new RangeError(
      `byteLength must be >= ${config.crypto.random.minByteLength} for adequate entropy (got ${n})`,
    );
  }
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}
