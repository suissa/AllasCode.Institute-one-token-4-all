import { describe, it, expect, vi } from 'vitest';
import { DPoPClient } from '../../src/client/DPoPClient.js';
import { MemoryKeyStore } from '../../src/storage/MemoryKeyStore.js';

/**
 * Chaos tests — inject random failures and unusual server behavior into the
 * fetch layer, verify the client degrades gracefully (no infinite loops,
 * no silent successes, no panic crashes).
 */

function jsonResponse(status: number, body: unknown, nonce?: string): Response {
  const headers = new Headers();
  if (nonce !== undefined) headers.set('DPoP-Nonce', nonce);
  return new Response(JSON.stringify(body), { status, headers }) as unknown as Response;
}

describe('Chaos: random fetch failures', () => {
  it('survives a network rejection', async () => {
    const fetch = vi.fn(async () => {
      throw new TypeError('fetch failed: ECONNRESET');
    }) as unknown as typeof fetch;
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: new MemoryKeyStore(),
      fetch,
    });
    await expect(client.refresh({ refreshToken: 'RT' })).rejects.toThrow(/ECONNRESET/);
  });

  it('survives a 500 server error', async () => {
    const fetch = vi.fn(async () =>
      new Response('internal error', { status: 500 }) as unknown as Response,
    ) as unknown as typeof fetch;
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: new MemoryKeyStore(),
      fetch,
    });
    await expect(client.refresh({ refreshToken: 'RT' })).rejects.toThrow();
  });

  it('survives a non-JSON success response', async () => {
    const fetch = vi.fn(async () =>
      new Response('OK', { status: 200 }) as unknown as Response,
    ) as unknown as typeof fetch;
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: new MemoryKeyStore(),
      fetch,
    });
    // json() will throw; verify the client surfaces it rather than hanging
    await expect(client.refresh({ refreshToken: 'RT' })).rejects.toThrow();
  });

  it('survives a 200 with malformed JSON body', async () => {
    const fetch = vi.fn(async () =>
      new Response('{"access_token":', { status: 200, headers: { 'content-type': 'application/json' } }) as unknown as Response,
    ) as unknown as typeof fetch;
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: new MemoryKeyStore(),
      fetch,
    });
    await expect(client.refresh({ refreshToken: 'RT' })).rejects.toThrow();
  });

  it('does not infinite-loop when AS returns use_dpop_nonce with NO nonce header', async () => {
    let calls = 0;
    const fetch = vi.fn(async () => {
      calls++;
      return jsonResponse(400, { error: 'use_dpop_nonce' }); // no DPoP-Nonce header
    }) as unknown as typeof fetch;
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: new MemoryKeyStore(),
      fetch,
    });
    await expect(client.refresh({ refreshToken: 'RT' })).rejects.toThrow(/use_dpop_nonce/);
    // Should attempt exactly once — no fresh nonce means no retry.
    expect(calls).toBe(1);
  });

  it('recovers when a transient network error gives way to success', async () => {
    let calls = 0;
    const fetch = vi.fn(async () => {
      calls++;
      if (calls === 1) throw new TypeError('transient network error');
      return jsonResponse(200, { access_token: 'AT', token_type: 'Bearer' });
    }) as unknown as typeof fetch;
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: new MemoryKeyStore(),
      fetch,
    });
    await expect(client.refresh({ refreshToken: 'RT' })).rejects.toThrow(/transient/);
    // Re-call: the next response is the success.
    const set = await client.refresh({ refreshToken: 'RT' });
    expect(set.accessToken).toBe('AT');
  });

  it('nonce-only response (no body) still updates the nonce cache', async () => {
    let calls = 0;
    const fetch = vi.fn(async () => {
      calls++;
      if (calls === 1) return jsonResponse(400, { error: 'use_dpop_nonce' }, 'NEW-NCE');
      return jsonResponse(200, { access_token: 'AT', token_type: 'Bearer' });
    }) as unknown as typeof fetch;
    const client = new DPoPClient({
      tokenEndpoint: 'https://as.example.com/token',
      clientId: 'c',
      keyStore: new MemoryKeyStore(),
      fetch,
    });
    await client.refresh({ refreshToken: 'RT' });
    expect(client.getNonce()).toBe('NEW-NCE');
  });
});
