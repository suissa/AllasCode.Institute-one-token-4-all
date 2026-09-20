# one-token-4-all

> One DPoP token to rule them ALL.

Canonical OAuth 2.0 **DPoP** (RFC 9449) token manager — pure WebCrypto, zero
runtime deps, ESM-only, Node 18+ and modern browsers.

## Highlights

- **Non-extractable private key** — generated and signed inside WebCrypto, can
  never leave the sandbox / hardware keystore.
- **ECDSA P-256 over SHA-256** — only curve required by RFC 9449.
- **Raw IEEE P1363 signatures** — no DER round-trip (WebCrypto already emits
  the right 64-byte format for P-256).
- **Single-retry `use_dpop_nonce` loop** — RFC 9449 §9 compliant, fails
  fast on persistent challenges (no infinite recursion).
- **Pluggable `KeyStore`** — `MemoryKeyStore` ships in the box; bring your own
  for IndexedDB / Node master-key / WebAuthn PRF.
- **LinearAutoDestroy** — per-request keystroke-style "use-and-throw" mode
  (UbiQUIC semantics). Each token request uses a fresh key pair and wipes
  references on completion. Opt-in via `client.ephemeralKeys: true` in
  `configs/core.yml` or via constructor config.
- **Everything as Code** — every runtime tunable lives in `configs/core.yml`.
  No magic numbers in source; protocol invariants are hardcoded with literal
  types and YAML deviations are rejected at startup.

## Install

```bash
npm install @allascode.institute/one-token-4-all
```

## Configuration

Everything is driven by `configs/core.yml`. Protocol-mandated values (curve
P-256, alg ES256, typ `dpop+jwt`, ATH = `sha256(token)`, sanitizeHTU strips
query/hash) are NOT configurable — they are hardcoded and any attempt to
override via YAML throws at startup.

```yaml
crypto:
  random:
    minByteLength: 16
    defaultByteLength: 32
  pkce:
    verifierByteLength: 32
  keypair:
    curve: P-256
    hash: SHA-256
    extractablePrivate: false
proof:
  jti:
    randomByteLength: 24
  iat:
    clockSkewSeconds: 30
client:
  http:
    defaultMethod: POST
    timeoutMs: 30000
  nonce:
    maxRetries: 1
  ephemeralKeys: false   # set true for LinearAutoDestroy (use-and-throw)
security:
  immediateKeyWipe: true
  requireClientId: true
```

Load explicitly or fall back to the built-in defaults:

```ts
import { DPoPClient, MemoryKeyStore, loadConfig } from '@purecore/one-token-4-all';

const cfg = loadConfig('./configs/core.yml');
```

## Quick start

```ts
import { DPoPClient, MemoryKeyStore, generatePKCE } from '@purecore/one-token-4-all';

// 1. Generate PKCE pair for the authorization redirect.
const { codeVerifier, codeChallenge, codeChallengeMethod } = await generatePKCE();
// put codeChallenge + codeChallengeMethod on the `redirect(user)` call.

// 2. Bootstrap the client (pass `config` to override YAML).
const client = new DPoPClient({
  tokenEndpoint: 'https://oauth2.googleapis.com/token',
  clientId: 'YOUR_CLIENT_ID',
  keyStore: new MemoryKeyStore(),
});

// 3. Exchange the code (after user returns).
const tokens = await client.exchangeCode({
  code: 'AUTH_CODE_FROM_REDIRECT',
  codeVerifier,
  redirectUri: 'https://your.app/callback',
});

// 4. Refresh later. DPoP nonce challenge handled automatically.
const next = await client.refresh({ refreshToken: tokens.refreshToken! });
```

## LinearAutoDestroy (per-request ephemeral keys)

Enable via YAML (`client.ephemeralKeys: true`) or via constructor config. When
on, every token endpoint request cycle (original + nonce retry) uses a
freshly-generated key pair; the previous pair's references are wiped as soon
as the cycle completes — regardless of success or failure.

```ts
import { defaultConfig } from '@purecore/one-token-4-all';

const client = new DPoPClient({
  tokenEndpoint: 'https://as.example.com/token',
  clientId: 'cid',
  keyStore: new MemoryKeyStore(),
  config: {
    ...defaultConfig,
    client: { ...defaultConfig.client, ephemeralKeys: true },
  },
});
```

⚠ RFC 9449 §6.5 caveat: a standards-compliant AS binds the refresh token to
the public key of the proof that obtained it. With ephemeral keys the public
key CHANGES on every refresh, so the AS will reject subsequent refreshes
with `invalid_dpop_proof`. Use ephemeral mode only for one-shot flows
(`client_credentials`, or experimental setups against a non-strict AS).

Session-bound destroy (always available, even when ephemeral mode is off):

```ts
await client.destroyKeys(); // wipes the persisted key pair
```

## API surface

| Function | What it does |
|---|---|
| `generateDPoPKeyPair()` | P-256 ECDSA pair, private key `extractable: false` |
| `exportPublicJWK(publicKey)` | `{kty:'EC', crv:'P-256', x, y}` in base64url |
| `createDPoPProof({...})` | Build + sign a DPoP Proof JWT |
| `verifyDPoPProof(jwt)` | Verify signature + `typ` + `alg` |
| `sanitizeHTU(url)` | Strip query/hash → `origin + pathname` |
| `generatePKCE()` | `{codeVerifier, codeChallenge, method:'S256'}` |
| `sha256(input)` / `calculateATH(token)` / `calculateAuthCodeJti(code)` | Hash helpers |
| `generateRandomString(n)` | Cryptographic random base64url |
| `base64UrlEncode/Decode` (and friends) | RFC 7515 §2 helpers |
| `loadConfig(path?)` | Read + validate YAML; defaults otherwise |
| `defaultConfig` | Frozen baseline used when no YAML is supplied |
| `DPoPClient` | High-level: code exchange, refresh, nonce retry, ephemeral mode |
| `KeyStore` / `MemoryKeyStore` | Pluggable key persistence (incl. `destroy()`) |

## Security invariants

1. **Private key is non-extractable.** Thwarts XSS-based exfiltration.
2. **Public key JWK is the minimum shape.** No `d`, no algorithm metadata.
3. **Signature is raw IEEE P1363 (64 bytes for P-256).** No DER round-trip.
4. **DPoP nonce retry is bounded.** At most `config.client.nonce.maxRetries` (default 1).
5. **No `crypto.subtle.importKey` of untrusted JWKs without `extractable: true`
   and `['verify']` only** — private keys are never imported from external
   payloads.
6. **YAML deviations from protocol are rejected at startup**, not silently
   overridden.

## Test suite

The repo ships nine test categories — run with `npm test`:

| Category | File | Coverage |
|---|---|---|
| Unit | `test/crypto/`, `test/proof/`, `test/storage/`, `test/client/` | crypto primitives, proof create/verify, KeyStore, client basics |
| Integration | `test/integration/dpop-flow.test.ts` | full DPoP flows against mocked AS, nonce handshake, token caching |
| BDD | `test/bdd/proof-lifecycle.test.ts` | Given/When/Then scenarios |
| Security | `test/security/extraction.test.ts` | non-extractable, alg confusion, jwk tamper, replay |
| Load | `test/load/parallel-proofs.test.ts` | configurable parallel proofs |
| Stress | `test/stress/keygen-pressure.test.ts` | configurable cycle count |
| Chaos | `test/chaos/fetch-failures.test.ts` | injected network/server failures |
| Benchmark | `test/benchmark/keygen-throughput.bench.ts` | tinybench hot-path throughput |
| E2E | `test/e2e/as-flow.test.ts` | real local HTTP server as AS |

All counts (cycles, parallelism, iterations) come from `configs/core.yml` —
tune them and re-run.

## License

MIT
