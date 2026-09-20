import { describe, it, expect } from 'vitest';
import { MemoryKeyStore } from '../../src/storage/MemoryKeyStore.js';
import { generateDPoPKeyPair } from '../../src/crypto/keypair.js';

describe('MemoryKeyStore — LinearAutoDestroy', () => {
  it('destroy() marks the key as destroyed and load() returns null', async () => {
    const store = new MemoryKeyStore();
    const keys = await generateDPoPKeyPair();
    await store.save(keys);
    expect(await store.load()).not.toBeNull();

    await store.destroy(keys);
    expect(await store.load()).toBeNull();
    expect(store.isDestroyed(keys)).toBe(true);
  });

  it('destroy() of an unsaved key is a no-op', async () => {
    const store = new MemoryKeyStore();
    const keys = await generateDPoPKeyPair();
    await store.destroy(keys); // never saved
    expect(await store.load()).toBeNull();
  });

  it('destroy() of a non-matching key does not affect the saved key', async () => {
    const store = new MemoryKeyStore();
    const saved = await generateDPoPKeyPair();
    const other = await generateDPoPKeyPair();
    await store.save(saved);

    await store.destroy(other);
    expect(await store.load()).not.toBeNull();
    expect((await store.load())!.privateKey).toBe(saved.privateKey);
  });

  it('is idempotent — destroying twice does not throw', async () => {
    const store = new MemoryKeyStore();
    const keys = await generateDPoPKeyPair();
    await store.save(keys);
    await store.destroy(keys);
    await expect(store.destroy(keys)).resolves.toBeUndefined();
  });

  it('after destroy(), saving a new key works again', async () => {
    const store = new MemoryKeyStore();
    const first = await generateDPoPKeyPair();
    const second = await generateDPoPKeyPair();
    await store.save(first);
    await store.destroy(first);
    await store.save(second);
    const loaded = await store.load();
    expect(loaded!.privateKey).toBe(second.privateKey);
  });

  it('clear() is equivalent to destroying the current key', async () => {
    const store = new MemoryKeyStore();
    const keys = await generateDPoPKeyPair();
    await store.save(keys);
    await store.clear();
    expect(await store.load()).toBeNull();
    expect(store.isDestroyed(keys)).toBe(true);
  });

  it('destroy() does not throw when the passed key was saved then cleared', async () => {
    const store = new MemoryKeyStore();
    const keys = await generateDPoPKeyPair();
    await store.save(keys);
    await store.clear();
    await expect(store.destroy(keys)).resolves.toBeUndefined();
  });
});
