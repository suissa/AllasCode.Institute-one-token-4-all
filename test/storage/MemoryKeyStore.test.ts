import { describe, it, expect } from 'vitest';
import { MemoryKeyStore } from '../../src/storage/MemoryKeyStore.js';
import { generateDPoPKeyPair } from '../../src/crypto/keypair.js';

describe('MemoryKeyStore', () => {
  it('returns null when empty', async () => {
    const store = new MemoryKeyStore();
    expect(await store.load()).toBeNull();
  });

  it('round-trips a generated key pair', async () => {
    const store = new MemoryKeyStore();
    const keys = await generateDPoPKeyPair();
    await store.save(keys);
    const loaded = await store.load();
    expect(loaded).not.toBeNull();
    expect(loaded!.publicKey).toBe(keys.publicKey);
    expect(loaded!.privateKey).toBe(keys.privateKey);
  });

  it('clear() forgets the key pair', async () => {
    const store = new MemoryKeyStore();
    await store.save(await generateDPoPKeyPair());
    await store.clear();
    expect(await store.load()).toBeNull();
  });

  it('save() replaces an existing entry', async () => {
    const store = new MemoryKeyStore();
    const k1 = await generateDPoPKeyPair();
    const k2 = await generateDPoPKeyPair();
    await store.save(k1);
    await store.save(k2);
    const loaded = await store.load();
    expect(loaded!.publicKey).toBe(k2.publicKey);
  });
});
