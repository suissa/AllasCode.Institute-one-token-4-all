import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DPoPClient } from '../../src/client/DPoPClient.js';
import { MemoryKeyStore } from '../../src/storage/MemoryKeyStore.js';
import { verifyDPoPProof } from '../../src/proof/verifyDPoPProof.js';
import { base64UrlToBytes } from '../../src/crypto/base64url.js';

/**
 * Integration tests — these exercise the full DPoPClient stack against a
 * mocked AS, verifying:
 *   - the token endpoint actually receives a structurally valid DPoP proof
 *   - the DPoP-Nonce handshake works end-to-end
 *   - token caching, refresh rotation, and error semantics
 */

function asResponse(status: number, body: unknown, nonce?: string): Response {
  const headers = new Headers();
  if (nonce !== undefined) headers.set('DPoP-Nonce', nonce);
  return new Response(JSON.stringify(body), { status, headers }) as unknown as Response;
}

describe('Integration: full DPoP flow', () => {
  let issuedNonces: string[];
  let receivedProofs: string[];

  beforeEach(() => {
    issuedNonces = [];
    receivedProofs = [];
  });

  function makeAS(handlers: Array<(req: { dpop: string | null; body: URLSearchParams }) => { status: number; body: unknown; nonce?: string }>) {
    let callIndex = 0;
    return vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      const dpop = headers['DPoP'] ?? headers['dpop'] ?? null;
      if (dpop) receivedProofs.push(dpop);
      const body = new URLSearchParams(String(init?.body ?? ''));
      const handler = handlers[callIndex++];
      if (!handler) throw new Error(`Unexpected call #${callIndex}`);
      const result = handler({ dpop, body });
      if (result.nonce) issuedNonces.push(result.nonce);
      return asResponse(result.status, result.body, result.nonce);
    }) as unknown as typeof fetch;
  }

  it('code exchange round-trips a verifiable proof to the AS', async () => {
    const fetchImpl = makeAS([
      ({ dpop }) => {
        expect(dpop).toBeTruthy();
        return {
          status: 200,
          body: { access_token: 'AT0', token_type: 'Bearer', expires_in: 3600, refresh_token: 'RT0' },
        };
      },
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'cid',
      keyStore: new MemoryKeyStore(),
      fetch: fetchImpl,
    });
    const set = await client.exchangeCode({ code: 'AUTH-CODE', codeVerifier: 'verifier', redirectUri: 'https://app/cb' });
    expect(set.accessToken).toBe('AT0');
    expect(set.refreshToken).toBe('RT0');
    expect(receivedProofs).toHaveLength(1);

    // Server-side verify (what an AS would do)
    const verify = await verifyDPoPProof(receivedProofs[0]!);
    expect(verify.isValid).toBe(true);
    const payload = verify.payload!;
    expect(payload['htm']).toBe('POST');
    expect(payload['htu']).toBe('https://as.example.com/token');
    expect(payload['jti']).toBeTruthy();
  });

  it('preserves the refresh token across refresh calls when AS does not rotate', async () => {
    const fetchImpl = makeAS([
      () => ({ status: 200, body: { access_token: 'AT0', token_type: 'Bearer', expires_in: 60, refresh_token: 'RT0' } }),
      () => ({ status: 200, body: { access_token: 'AT1', token_type: 'Bearer', expires_in: 60 } }),
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'cid',
      keyStore: new MemoryKeyStore(),
      fetch: fetchImpl,
    });
    await client.exchangeCode({ code: 'C', codeVerifier: 'V', redirectUri: 'R' });
    const next = await client.refresh({ refreshToken: 'RT0' });
    expect(next.refreshToken).toBe('RT0'); // preserved from previous set
  });

  it('rotates refresh token when AS returns a new one', async () => {
    const fetchImpl = makeAS([
      () => ({ status: 200, body: { access_token: 'AT0', token_type: 'Bearer', refresh_token: 'RT0' } }),
      () => ({ status: 200, body: { access_token: 'AT1', token_type: 'Bearer', refresh_token: 'RT1' } }),
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'cid',
      keyStore: new MemoryKeyStore(),
      fetch: fetchImpl,
    });
    await client.exchangeCode({ code: 'C', codeVerifier: 'V', redirectUri: 'R' });
    const next = await client.refresh({ refreshToken: 'RT0' });
    expect(next.refreshToken).toBe('RT1');
  });

  it('nonce handshake re-issues proof with the new nonce', async () => {
    const fetchImpl = makeAS([
      () => ({ status: 400, body: { error: 'use_dpop_nonce' }, nonce: 'FRESH-NONCE-A' }),
      ({ dpop }) => {
        // The retry proof must include the fresh nonce
        const headerB64 = dpop!.split('.')[0]!;
        const pad = '='.repeat((4 - headerB64.length % 4) % 4);
        const payloadB64 = dpop!.split('.')[1]!;
        const pad2 = '='.repeat((4 - payloadB64.length % 4) % 4);
        const payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadB64)));
        expect(payload.nonce).toBe('FRESH-NONCE-A');
        // silence unused var lint
        void headerB64; void pad; void pad2;
        return { status: 200, body: { access_token: 'AT1', token_type: 'Bearer' } };
      },
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'cid',
      keyStore: new MemoryKeyStore(),
      fetch: fetchImpl,
    });
    const set = await client.refresh({ refreshToken: 'RT' });
    expect(set.accessToken).toBe('AT1');
    expect(issuedNonces).toEqual(['FRESH-NONCE-A']);
    expect(client.getNonce()).toBe('FRESH-NONCE-A');
  });

  it('error response carries status and body for callers', async () => {
    const fetchImpl = makeAS([
      () => ({ status: 403, body: { error: 'access_denied', error_description: 'user rejected' } }),
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'cid',
      keyStore: new MemoryKeyStore(),
      fetch: fetchImpl,
    });
    try {
      await client.refresh({ refreshToken: 'RT' });
      throw new Error('should have thrown');
    } catch (err: any) {
      expect(err.status).toBe(403);
      expect(err.body.error).toBe('access_denied');
      expect(err.message).toContain('access_denied');
      expect(err.message).toContain('user rejected');
    }
  });

  it('stops after the configured number of nonce retries', async () => {
    const fetchImpl = makeAS([
      () => ({ status: 400, body: { error: 'use_dpop_nonce' }, nonce: 'n1' }),
      () => ({ status: 400, body: { error: 'use_dpop_nonce' }, nonce: 'n2' }),
      () => ({ status: 400, body: { error: 'use_dpop_nonce' }, nonce: 'n3' }),
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'cid',
      keyStore: new MemoryKeyStore(),
      fetch: fetchImpl,
    });
    await expect(client.refresh({ refreshToken: 'RT' })).rejects.toThrow(/use_dpop_nonce/);
    // 1 original + 1 retry = 2 (default maxRetries=1)
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
});
