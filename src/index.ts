// Config (Everything as Code)
export {
  loadConfig,
  defaultConfig,
  freezeConfig,
  type CoreConfig,
} from './config.js';

// Crypto helpers (skill-prescribed API surface)
export {
  bytesToBase64Url,
  base64UrlToBytes,
  stringToBase64Url,
  base64UrlToString,
  base64UrlEncode,
  base64UrlDecode,
} from './crypto/base64url.js';

export {
  sha256,
  calculateATH,
  calculateAuthCodeJti,
} from './crypto/sha256.js';

export { generateRandomString } from './crypto/random.js';

export {
  generateDPoPKeyPair,
  exportPublicJWK,
  type DPoPKeyPair,
  type PublicJWK,
} from './crypto/keypair.js';

export {
  generatePKCE,
  type PKCEPair,
} from './crypto/pkce.js';

// Proof (skill-prescribed API surface)
export { sanitizeHTU } from './proof/sanitizeHTU.js';
export {
  createDPoPProof,
  type CreateDPoPProofOptions,
} from './proof/createDPoPProof.js';
export {
  verifyDPoPProof,
  type VerifyDPoPProofResult,
} from './proof/verifyDPoPProof.js';

// Storage
export type { KeyStore, StoredKey } from './storage/KeyStore.js';
export { MemoryKeyStore } from './storage/MemoryKeyStore.js';

// Client
export { DPoPClient } from './client/DPoPClient.js';
export type {
  TokenSet,
  TokenEndpointResponse,
  TokenEndpointError,
  DPoPClientOptions,
  ExchangeCodeOptions,
  RefreshOptions,
} from './client/types.js';
