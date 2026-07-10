import { beforeEach, describe, expect, it } from 'vitest';
import {
  InMemorySignalProtocolStore,
  MessageType,
  SignalProtocolManager,
  type KeyServerClient,
  type PublishedKeys,
  type SerializedPreKeyBundle,
} from '../index';

/**
 * Minimal fake key server: stores published keys per user and serves
 * bundles, consuming one one-time prekey per fetch (as the real backend
 * must do atomically — X3DH §3.2).
 */
class FakeKeyServer implements KeyServerClient {
  readonly published = new Map<string, PublishedKeys>();

  async publishKeys(userId: string, keys: PublishedKeys): Promise<void> {
    this.published.set(userId, keys);
  }

  async fetchPreKeyBundle(userId: string): Promise<SerializedPreKeyBundle> {
    const keys = this.published.get(userId);
    if (!keys) throw new Error(`No keys published for ${userId}`);
    const oneTimePreKey = keys.oneTimePreKeys.shift(); // consume (may run out)
    return {
      registrationId: keys.registrationId,
      identityKey: keys.identityKey,
      signedPreKey: keys.signedPreKey,
      ...(oneTimePreKey && { oneTimePreKey }),
    };
  }
}

let server: FakeKeyServer;
let aliceStore: InMemorySignalProtocolStore;
let bobStore: InMemorySignalProtocolStore;
let alice: SignalProtocolManager;
let bob: SignalProtocolManager;

beforeEach(async () => {
  server = new FakeKeyServer();
  aliceStore = new InMemorySignalProtocolStore();
  bobStore = new InMemorySignalProtocolStore();
  alice = new SignalProtocolManager('alice', aliceStore, server);
  bob = new SignalProtocolManager('bob', bobStore, server);
  await alice.initialize();
  await bob.initialize();
});

describe('SignalProtocolManager', () => {
  it('initialize publishes identity, signed prekey and 100 one-time prekeys', async () => {
    const keys = server.published.get('alice')!;
    expect(keys.registrationId).toBeGreaterThan(0);
    expect(keys.identityKey).toBeTypeOf('string');
    expect(keys.signedPreKey.signature.length).toBeGreaterThan(0);
    expect(keys.oneTimePreKeys).toHaveLength(100);
    expect(await aliceStore.getIdentityKeyPair()).toBeDefined();
  });

  it('initialize is idempotent (existing identity untouched)', async () => {
    const before = await aliceStore.getIdentityKeyPair();
    await alice.initialize();
    expect(await aliceStore.getIdentityKeyPair()).toBe(before);
  });

  it('full conversation: session bootstrap, replies, both directions', async () => {
    const first = await alice.encryptMessage('bob', 'salut bob');
    expect(first.type).toBe(MessageType.PreKey);
    expect(await bob.decryptMessage('alice', first)).toBe('salut bob');

    const reply = await bob.encryptMessage('alice', 'salut alice');
    expect(reply.type).toBe(MessageType.Signal);
    expect(await alice.decryptMessage('bob', reply)).toBe('salut alice');

    for (let i = 0; i < 5; i++) {
      expect(await bob.decryptMessage('alice', await alice.encryptMessage('bob', `a${i}`)))
        .toBe(`a${i}`);
      expect(await alice.decryptMessage('bob', await bob.encryptMessage('alice', `b${i}`)))
        .toBe(`b${i}`);
    }

    // Exactly one bundle fetch happened: 100 → 99 one-time prekeys left.
    expect(server.published.get('bob')!.oneTimePreKeys).toHaveLength(99);
  });

  it('ciphertext bodies never contain the plaintext', async () => {
    const message = await alice.encryptMessage('bob', 'top secret payload');
    expect(message.body).not.toContain('top secret payload');
    expect(message.body).not.toContain('secret');
  });

  it('works when the server has run out of one-time prekeys', async () => {
    server.published.get('bob')!.oneTimePreKeys = [];
    const message = await alice.encryptMessage('bob', 'no opk left');
    expect(await bob.decryptMessage('alice', message)).toBe('no opk left');
  });

  it('supports three-party pairwise sessions independently', async () => {
    const carolStore = new InMemorySignalProtocolStore();
    const carol = new SignalProtocolManager('carol', carolStore, server);
    await carol.initialize();

    expect(await bob.decryptMessage('alice', await alice.encryptMessage('bob', 'to bob')))
      .toBe('to bob');
    expect(await carol.decryptMessage('alice', await alice.encryptMessage('carol', 'to carol')))
      .toBe('to carol');
    expect(await alice.decryptMessage('carol', await carol.encryptMessage('alice', 'from carol')))
      .toBe('from carol');
  });
});
