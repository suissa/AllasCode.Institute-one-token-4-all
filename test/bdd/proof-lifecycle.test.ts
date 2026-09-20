import { describe, it, expect, vi } from 'vitest';
import { DPoPClient } from '../../src/client/DPoPClient.js';
import { MemoryKeyStore } from '../../src/storage/MemoryKeyStore.js';

/**
 * BDD-style scenarios — Given / When / Then.
 *
 * Vitest does not ship a Gherkin parser; the `describe`/`it` blocks are
 * styled in plain English so a non-engineer can read them top-to-bottom as
 * a behavioral spec.
 */

function asResponse(status: number, body: unknown, nonce?: string): Response {
  const headers = new Headers();
  if (nonce !== undefined) headers.set('DPoP-Nonce', nonce);
  return new Response(JSON.stringify(body), { status, headers }) as unknown as Response;
}

describe('Feature: DPoP-bound refresh tokens', () => {
  describe('Scenario: successful token refresh', () => {
    it('Given a valid refresh token, When the client refreshes, Then it receives a new access token bound to the same DPoP key', async () => {
      const fetch = vi.fn(async () =>
        asResponse(200, { access_token: 'NEW-AT', token_type: 'Bearer', expires_in: 3600 }),
      ) as unknown as typeof fetch;
      const store = new MemoryKeyStore();
      const client = new DPoPClient({
        tokenEndpoint: 'https://as.example.com/token',
        clientId: 'cid',
        keyStore: store,
        fetch,
      });

      const set = await client.refresh({ refreshToken: 'OLD-RT' });

      expect(set.accessToken).toBe('NEW-AT');
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(await store.load()).not.toBeNull();
    });
  });

  describe('Scenario: AS demands nonce', () => {
    it('Given the AS returns use_dpop_nonce, When the client retries, Then the retry proof carries the new nonce', async () => {
      let call = 0;
      const fetch = vi.fn(async () => {
        call++;
        if (call === 1) {
          return asResponse(400, { error: 'use_dpop_nonce' }, 'NONCE-42');
        }
        return asResponse(200, { access_token: 'AT', token_type: 'Bearer' });
      }) as unknown as typeof fetch;
      const client = new DPoPClient({
        tokenEndpoint: 'https://as.example.com/token',
        clientId: 'cid',
        keyStore: new MemoryKeyStore(),
        fetch,
      });

      const set = await client.refresh({ refreshToken: 'RT' });

      expect(set.accessToken).toBe('AT');
      expect(fetch).toHaveBeenCalledTimes(2);
      expect(client.getNonce()).toBe('NONCE-42');
    });
  });

  describe('Scenario: invalid refresh token', () => {
    it('Given an expired refresh token, When the client refreshes, Then the error propagates with status and body', async () => {
      const fetch = vi.fn(async () =>
        asResponse(401, { error: 'invalid_grant', error_description: 'token expired' }),
      ) as unknown as typeof fetch;
      const client = new DPoPClient({
        tokenEndpoint: 'https://as.example.com/token',
        clientId: 'cid',
        keyStore: new MemoryKeyStore(),
        fetch,
      });

      let caught: any;
      try {
        await client.refresh({ refreshToken: 'EXPIRED' });
      } catch (e) {
        caught = e;
      }

      expect(caught).toBeDefined();
      expect(caught.status).toBe(401);
      expect(caught.body.error).toBe('invalid_grant');
    });
  });

  describe('Scenario: LinearAutoDestroy — use-and-throw mode', () => {
    it('Given ephemeral mode is on, When the client refreshes twice, Then each request uses a fresh key', async () => {
      let call = 0;
      const jwkPerCall: string[] = [];
      const fetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
        call++;
        const dpop = (init?.headers as Record<string, string>)['DPoP']!;
        const headerB64 = dpop.split('.')[0]!;
        const pad = '='.repeat((4 - headerB64.length % 4) % 4);
        const json = Buffer.from(headerB64.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8');
        jwkPerCall.push(JSON.parse(json).jwk.x);
        return asResponse(200, { access_token: `AT${call}`, token_type: 'Bearer' });
      }) as unknown as typeof fetch;
      const { defaultConfig } = await import('../../src/config.js');
      const store = new MemoryKeyStore();
      const client = new DPoPClient({
        tokenEndpoint: 'https://as.example.com/token',
        clientId: 'cid',
        keyStore: store,
        config: { ...defaultConfig, client: { ...defaultConfig.client, ephemeralKeys: true } },
        fetch,
      });

      await client.refresh({ refreshToken: 'RT' });
      await client.refresh({ refreshToken: 'RT' });

      expect(jwkPerCall).toHaveLength(2);
      expect(jwkPerCall[0]).not.toBe(jwkPerCall[1]);
      expect(await store.load()).toBeNull();
    });
  });

  describe('Scenario: logout destroys everything', () => {
    it('Given an active session, When the user logs out, Then the DPoP key pair is wiped from the store', async () => {
      const fetch = vi.fn(async () =>
        asResponse(200, { access_token: 'AT', token_type: 'Bearer', refresh_token: 'RT' }),
      ) as unknown as typeof fetch;
      const store = new MemoryKeyStore();
      const client = new DPoPClient({
        tokenEndpoint: 'https://as.example.com/token',
        clientId: 'cid',
        keyStore: store,
        fetch,
      });
      await client.exchangeCode({ code: 'C', codeVerifier: 'V', redirectUri: 'R' });
      expect(await store.load()).not.toBeNull();

      await client.reset();

      expect(await store.load()).toBeNull();
      expect(client.getTokenSet()).toBeNull();
      expect(client.getNonce()).toBeNull();
    });
  });
});
