import { describe, it, expect, vi } from 'vitest';
import { DPoPClient } from '../../src/client/DPoPClient.js';
import { MemoryKeyStore } from '../../src/storage/MemoryKeyStore.js';
import { defaultConfig } from '../../src/config.js';

function jsonResponse(status: number, body: Record<string, unknown>, nonce?: string): Response {
  const headers = new Headers();
  if (nonce !== undefined) headers.set('DPoP-Nonce', nonce);
  return new Response(JSON.stringify(body), { status, headers }) as unknown as Response;
}

function fakeFetch(scripts: Array<{ status: number; body?: Record<string, unknown>; nonce?: string }>): {
  fetch: typeof fetch;
  calls: Array<{ url: string; init: RequestInit }>;
} {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  let i = 0;
  const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    const s = scripts[i++];
    if (!s) throw new Error(`Unexpected fetch call #${i}`);
    return jsonResponse(s.status, s.body ?? {}, s.nonce);
  }) as unknown as typeof fetch;
  return { fetch: fetchImpl, calls };
}

describe('DPoPClient — LinearAutoDestroy (ephemeralKeys)', () => {
  it('reports isEphemeral() based on config', () => {
    const ephemeral = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: new MemoryKeyStore(),
      config: { ...defaultConfig, client: { ...defaultConfig.client, ephemeralKeys: true } },
      fetch: fakeFetch([]).fetch,
    });
    const persistent = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: new MemoryKeyStore(),
      fetch: fakeFetch([]).fetch,
    });
    expect(ephemeral.isEphemeral()).toBe(true);
    expect(persistent.isEphemeral()).toBe(false);
  });

  it('in ephemeral mode, KeyStore never holds a key after a successful request', async () => {
    const store = new MemoryKeyStore();
    const { fetch, calls } = fakeFetch([
      { status: 200, body: { access_token: 'AT', token_type: 'Bearer', expires_in: 60 } },
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: store,
      config: { ...defaultConfig, client: { ...defaultConfig.client, ephemeralKeys: true } },
      fetch,
    });
    await client.refresh({ refreshToken: 'RT' });
    expect(calls).toHaveLength(1);
    // store was never given a persistent key
    expect(await store.load()).toBeNull();
  });

  it('in ephemeral mode, key pair generated for request #1 is destroyed before #2', async () => {
    const store = new MemoryKeyStore();
    const { fetch, calls } = fakeFetch([
      { status: 200, body: { access_token: 'AT1', token_type: 'Bearer' } },
      { status: 200, body: { access_token: 'AT2', token_type: 'Bearer' } },
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: store,
      config: { ...defaultConfig, client: { ...defaultConfig.client, ephemeralKeys: true } },
      fetch,
    });
    await client.refresh({ refreshToken: 'RT' });
    await client.refresh({ refreshToken: 'RT' });

    const jwks: string[] = calls.map((c) => {
      const dpop = (c.init.headers as Record<string, string>)['DPoP'];
      const headerB64 = dpop.split('.')[0]!;
      const json = Buffer.from(headerB64.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - headerB64.length % 4) % 4), 'base64').toString('utf8');
      return JSON.parse(json).jwk.x;
    });
    // Each proof uses a DIFFERENT key (jwk.x changes)
    expect(jwks[0]).not.toBe(jwks[1]);
  });

  it('in ephemeral mode, destroys even on nonce retry failure', async () => {
    const store = new MemoryKeyStore();
    const { fetch } = fakeFetch([
      { status: 400, body: { error: 'use_dpop_nonce' }, nonce: 'n1' },
      { status: 400, body: { error: 'use_dpop_nonce' }, nonce: 'n2' },
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: store,
      config: { ...defaultConfig, client: { ...defaultConfig.client, ephemeralKeys: true } },
      fetch,
    });
    await expect(client.refresh({ refreshToken: 'RT' })).rejects.toThrow();
    // even after failure, store is empty
    expect(await store.load()).toBeNull();
  });

  it('persistent mode (default) DOES keep the key across requests', async () => {
    const store = new MemoryKeyStore();
    const { fetch, calls } = fakeFetch([
      { status: 200, body: { access_token: 'AT1', token_type: 'Bearer' } },
      { status: 200, body: { access_token: 'AT2', token_type: 'Bearer' } },
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: store,
      fetch,
    });
    await client.refresh({ refreshToken: 'RT' });
    await client.refresh({ refreshToken: 'RT' });
    const jwks: string[] = calls.map((c) => {
      const dpop = (c.init.headers as Record<string, string>)['DPoP'];
      const headerB64 = dpop.split('.')[0]!;
      const pad = '='.repeat((4 - headerB64.length % 4) % 4);
      const json = Buffer.from(headerB64.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8');
      return JSON.parse(json).jwk.x;
    });
    expect(jwks[0]).toBe(jwks[1]);
  });

  it('destroyKeys() wipes the persisted key (session boundary)', async () => {
    const store = new MemoryKeyStore();
    const { fetch } = fakeFetch([
      { status: 200, body: { access_token: 'AT', token_type: 'Bearer' } },
    ]);
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: store,
      fetch,
    });
    await client.refresh({ refreshToken: 'RT' });
    expect(await store.load()).not.toBeNull();

    await client.destroyKeys();
    expect(await store.load()).toBeNull();
  });
});
