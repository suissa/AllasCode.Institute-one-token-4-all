import { describe, it, expect, vi } from 'vitest';
import { DPoPClient } from '../../src/client/DPoPClient.js';
import { MemoryKeyStore } from '../../src/storage/MemoryKeyStore.js';
import type { TokenEndpointResponse, TokenEndpointError } from '../../src/client/types.js';
import { base64UrlToBytes } from '../../src/crypto/base64url.js';

interface FakeResponseInit {
  status: number;
  body?: TokenEndpointResponse | TokenEndpointError;
  nonce?: string | null;
}

function jsonResponse({ status, body, nonce }: FakeResponseInit): Response {
  const headers = new Headers();
  if (nonce !== undefined && nonce !== null) headers.set('DPoP-Nonce', nonce);
  return new Response(JSON.stringify(body ?? {}), {
    status,
    headers,
  });
}

function makeFetch(responses: FakeResponseInit[]): typeof fetch {
  let i = 0;
  return vi.fn(async () => {
    const r = responses[i++];
    if (!r) throw new Error(`fetch called ${i} times but only ${responses.length} responses scripted`);
    return jsonResponse(r) as unknown as Response;
  }) as unknown as typeof fetch;
}

describe('DPoPClient', () => {
  it('throws if tokenEndpoint/clientId/keyStore missing', () => {
    expect(() => new DPoPClient({ tokenEndpoint: '', clientId: 'c', keyStore: new MemoryKeyStore() })).toThrow();
    expect(() => new DPoPClient({ tokenEndpoint: 'u', clientId: '', keyStore: new MemoryKeyStore() })).toThrow();
    expect(() => new DPoPClient({ tokenEndpoint: 'u', clientId: 'c', keyStore: null as any })).toThrow();
  });

  it('exchangeCode POSTs to token endpoint with DPoP header and parses response', async () => {
    const fetchImpl = makeFetch([
      { status: 200, body: { access_token: 'AT', token_type: 'Bearer', expires_in: 3600, refresh_token: 'RT' } },
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'cid',
      keyStore: new MemoryKeyStore(),
      fetch: fetchImpl,
    });
    const set = await client.exchangeCode({ code: 'C', codeVerifier: 'V', redirectUri: 'https://app/cb' });
    expect(set.accessToken).toBe('AT');
    expect(set.tokenType).toBe('Bearer');
    expect(set.refreshToken).toBe('RT');
    expect(set.expiresAt).toBeGreaterThan(Date.now());

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = (fetchImpl as any).mock.calls[0];
    expect(url).toBe('https://as.example.com/token');
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers['DPoP']).toMatch(/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(headers['Content-Type']).toBe('application/x-www-form-urlencoded');
    expect((init as RequestInit).method).toBe('POST');
  });

  it('retries exactly once on use_dpop_nonce challenge with the new nonce', async () => {
    const fetchImpl = makeFetch([
      // First attempt: AS demands nonce
      { status: 400, body: { error: 'use_dpop_nonce' }, nonce: 'fresh-nonce-1' },
      // Second attempt should succeed and include the nonce claim
      { status: 200, body: { access_token: 'AT2', token_type: 'Bearer', expires_in: 60 } },
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'cid',
      keyStore: new MemoryKeyStore(),
      fetch: fetchImpl,
    });
    const set = await client.refresh({ refreshToken: 'RT' });
    expect(set.accessToken).toBe('AT2');
    expect(fetchImpl).toHaveBeenCalledTimes(2);

    // Second request body must include the nonce
    const secondCall = (fetchImpl as any).mock.calls[1];
    const secondDpop = (secondCall[1] as RequestInit).headers!['DPoP'] as string;
    const payloadB64 = secondDpop.split('.')[1]!;
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadB64)));
    expect(payload.nonce).toBe('fresh-nonce-1');

    // Nonce cached for next call
    expect(client.getNonce()).toBe('fresh-nonce-1');
  });

  it('does not infinite-retry on persistent use_dpop_nonce', async () => {
    const fetchImpl = makeFetch([
      { status: 400, body: { error: 'use_dpop_nonce' }, nonce: 'n1' },
      { status: 400, body: { error: 'use_dpop_nonce' }, nonce: 'n2' },
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'cid',
      keyStore: new MemoryKeyStore(),
      fetch: fetchImpl,
    });
    await expect(client.refresh({ refreshToken: 'RT' })).rejects.toThrow(/use_dpop_nonce/);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('propagates non-nonce errors with status and body', async () => {
    const fetchImpl = makeFetch([
      { status: 401, body: { error: 'invalid_grant', error_description: 'expired refresh token' } },
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'cid',
      keyStore: new MemoryKeyStore(),
      fetch: fetchImpl,
    });
    try {
      await client.refresh({ refreshToken: 'bad' });
      throw new Error('should have thrown');
    } catch (err: any) {
      expect(err.status).toBe(401);
      expect(err.body.error).toBe('invalid_grant');
      expect(err.message).toMatch(/invalid_grant/);
      expect(err.message).toMatch(/expired refresh token/);
    }
  });

  it('uses the same key pair across requests (does not regenerate)', async () => {
    const store = new MemoryKeyStore();
    const fetchImpl = makeFetch([
      { status: 200, body: { access_token: 'AT', token_type: 'Bearer' } },
      { status: 200, body: { access_token: 'AT2', token_type: 'Bearer' } },
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'cid',
      keyStore: store,
      fetch: fetchImpl,
    });
    await client.refresh({ refreshToken: 'RT' });
    await client.refresh({ refreshToken: 'RT' });
    const keys1 = await store.load();
    const keys2 = await store.load();
    expect(keys1).toBe(keys2);
  });

  it('reset() clears tokens and keys', async () => {
    const store = new MemoryKeyStore();
    const fetchImpl = makeFetch([
      { status: 200, body: { access_token: 'AT', token_type: 'Bearer', refresh_token: 'RT' } },
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'cid',
      keyStore: store,
      fetch: fetchImpl,
    });
    await client.refresh({ refreshToken: 'RT' });
    expect(client.getTokenSet()).not.toBeNull();
    await client.reset();
    expect(client.getTokenSet()).toBeNull();
    expect(await store.load()).toBeNull();
    expect(client.getNonce()).toBeNull();
  });
});
