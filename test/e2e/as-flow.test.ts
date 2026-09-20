import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { DPoPClient } from '../../src/client/DPoPClient.js';
import { MemoryKeyStore } from '../../src/storage/MemoryKeyStore.js';
import { verifyDPoPProof } from '../../src/proof/verifyDPoPProof.js';

/**
 * E2E test — spins up a real local HTTP server that pretends to be an
 * authorization server, then runs the full DPoP flow against it via
 * DPoPClient. Validates the on-wire behavior with no fetch mocking.
 */

interface ASState {
  boundPublicKey: { x: string; y: string } | null;
  accessToken: string;
  refreshToken: string;
  issuedNonces: Set<string>;
  failNext: number;
  forceUseDPoPNonceOnce: boolean;
}

function makeASServer(state: ASState): { server: Server; port: number } {
  const server = createServer((req, res) => {
    void handle(req, res);
  });

  async function handle(req: IncomingMessage, res: ServerResponse) {
    if (!req.url || !req.method) {
      res.writeHead(400).end();
      return;
    }

    // Pull the body for /token
    let body = '';
    req.setEncoding('utf8');
    for await (const chunk of req) body += chunk;

    if (req.url.startsWith('/token') && req.method === 'POST') {
      const params = new URLSearchParams(body);
      const grantType = params.get('grant_type');
      const dpopHeader = req.headers['dpop'];
      const nonceHeader = req.headers['dpop-nonce'] as string | undefined;

      if (state.forceUseDPoPNonceOnce) {
        state.forceUseDPoPNonceOnce = false;
        res.writeHead(400, { 'DPoP-Nonce': 'real-as-nonce' });
        res.end(JSON.stringify({ error: 'use_dpop_nonce' }));
        return;
      }

      if (Array.isArray(dpopHeader)) {
        res.writeHead(400).end(JSON.stringify({ error: 'invalid_dpop_proof' }));
        return;
      }
      if (!dpopHeader) {
        res.writeHead(400).end(JSON.stringify({ error: 'invalid_request', error_description: 'DPoP missing' }));
        return;
      }
      const verify = await verifyDPoPProof(dpopHeader);
      if (!verify.isValid) {
        res.writeHead(400).end(JSON.stringify({ error: 'invalid_dpop_proof', error_description: verify.error }));
        return;
      }
      const payload = verify.payload!;
      const jwk = (verify.header as { jwk: { x: string; y: string } }).jwk;

      // Initial code exchange — bind the public key
      if (grantType === 'authorization_code') {
        state.boundPublicKey = jwk;
        state.accessToken = `at-${Date.now()}`;
        state.refreshToken = `rt-${Date.now()}`;
        const freshNonce = `nonce-${Math.random().toString(36).slice(2)}`;
        state.issuedNonces.add(freshNonce);
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'DPoP-Nonce': freshNonce,
        });
        res.end(JSON.stringify({
          access_token: state.accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: state.refreshToken,
        }));
        return;
      }

      if (grantType === 'refresh_token') {
        // Enforce key continuity (per RFC 9449 §6.5)
        if (!state.boundPublicKey || jwk.x !== state.boundPublicKey.x || jwk.y !== state.boundPublicKey.y) {
          res.writeHead(400).end(JSON.stringify({ error: 'invalid_dpop_proof', error_description: 'key mismatch' }));
          return;
        }
        // Sanity: htm/htu
        if (payload['htm'] !== 'POST' || payload['htu'] !== 'http://127.0.0.1:' + ((req.socket.address() as { port: number }).port) + '/token') {
          res.writeHead(400).end(JSON.stringify({ error: 'invalid_dpop_proof', error_description: 'htm/htu mismatch' }));
          return;
        }
        state.accessToken = `at-${Date.now()}`;
        state.refreshToken = `rt-${Date.now()}`;
        const freshNonce = `nonce-${Math.random().toString(36).slice(2)}`;
        state.issuedNonces.add(freshNonce);
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'DPoP-Nonce': freshNonce,
        });
        res.end(JSON.stringify({
          access_token: state.accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: state.refreshToken,
        }));
        return;
      }

      res.writeHead(400).end(JSON.stringify({ error: 'unsupported_grant_type' }));
      return;
    }

    res.writeHead(404).end();
  }

  return { server, port: 0 }; // port assigned on listen
}

describe('E2E: DPoPClient ↔ real HTTP AS', () => {
  let server: Server;
  let port: number;
  let state: ASState;

  beforeEach(async () => {
    state = {
      boundPublicKey: null,
      accessToken: '',
      refreshToken: '',
      issuedNonces: new Set(),
      failNext: 0,
      forceUseDPoPNonceOnce: false,
    };
    const created = makeASServer(state);
    server = created.server;
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const addr = server.address();
    port = typeof addr === 'object' && addr ? addr.port : 0;
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('runs code exchange then refresh over real HTTP', async () => {
    const client = new DPoPClient({
      tokenEndpoint: `http://127.0.0.1:${port}/token`,
      clientId: 'cid',
      keyStore: new MemoryKeyStore(),
    });

    // 1. Code exchange
    const initial = await client.exchangeCode({
      code: 'AUTH-CODE',
      codeVerifier: 'verifier',
      redirectUri: 'https://app/cb',
    });
    expect(initial.accessToken).toBeTruthy();
    expect(initial.refreshToken).toBeTruthy();
    expect(state.boundPublicKey).not.toBeNull();

    // 2. Refresh (key continuity is enforced by the server)
    const refreshed = await client.refresh({ refreshToken: initial.refreshToken! });
    expect(refreshed.accessToken).not.toBe(initial.accessToken);
    expect(refreshed.refreshToken).not.toBe(initial.refreshToken);
    expect(state.issuedNonces.size).toBeGreaterThanOrEqual(2);
  });

  it('handles the use_dpop_nonce challenge transparently on a real server', async () => {
    state.forceUseDPoPNonceOnce = true;
    const client = new DPoPClient({
      tokenEndpoint: `http://127.0.0.1:${port}/token`,
      clientId: 'cid',
      keyStore: new MemoryKeyStore(),
    });
    // Use exchangeCode so the AS binds the client's public key first,
    // then the nonce challenge triggers on the very first request.
    const set = await client.exchangeCode({
      code: 'AUTH-CODE',
      codeVerifier: 'verifier',
      redirectUri: 'https://app/cb',
    });
    expect(set.accessToken).toBeTruthy();
    // The challenge response sent nonce 'real-as-nonce'; the client retry
    // should carry it. The successful response from the retry also carries
    // a fresh nonce, but the latest one we exposed in the test was the
    // challenge one. We just assert the nonce is non-null after the flow.
    expect(client.getNonce()).toBeTruthy();
  });
});
