import { beforeEach, describe, expect, it } from 'vitest';
import {
  InMemorySignalProtocolStore,
  MessageType,
  SignalProtocolManager,
  type GroupMessage,
  type KeyServerClient,
  type PublishedKeys,
  type SerializedPreKeyBundle,
  type SerializedSKDM,
} from '../index';
import { createSKDM, verifySKDM } from '../sender-keys/sender-key-distribution';
import { SenderKeyState } from '../sender-keys/sender-key-state';
import { generateIdentityKeyPair } from '../identity/identity-key';

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

  it('serializes concurrent decrypts per peer (no replay window)', async () => {
    // Establish the session and clear the handshake phase.
    expect(await bob.decryptMessage('alice', await alice.encryptMessage('bob', 'boot'))).toBe('boot');
    expect(await alice.decryptMessage('bob', await bob.encryptMessage('alice', 'ack'))).toBe('ack');

    const m0 = await alice.encryptMessage('bob', 'zero');
    const m1 = await alice.encryptMessage('bob', 'one');

    // Interleaved delivery: without per-peer serialization, both decrypts
    // start from the same stored state — the second one skips m0's key,
    // stores it, and the replay below would be ACCEPTED.
    const [p0, p1] = await Promise.all([
      bob.decryptMessage('alice', m0),
      bob.decryptMessage('alice', m1),
    ]);
    expect([p0, p1]).toEqual(['zero', 'one']);

    await expect(bob.decryptMessage('alice', m0)).rejects.toThrow();
    await expect(bob.decryptMessage('alice', m1)).rejects.toThrow();

    // Session still healthy afterwards.
    expect(await bob.decryptMessage('alice', await alice.encryptMessage('bob', 'two'))).toBe('two');
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

// ---------------------------------------------------------------------------
// Group messaging (Sender Keys)
// ---------------------------------------------------------------------------

/** Minimal SKDM mailbox: simulates distributing distribution messages
 *  between group members (in a real app this goes through 1:1 sessions). */
class SKDMMailbox {
  private readonly store = new Map<string, Map<string, SerializedSKDM>>(); // groupId → senderId

  send(groupId: string, skdm: SerializedSKDM): void {
    if (!this.store.has(groupId)) this.store.set(groupId, new Map());
    this.store.get(groupId)!.set(skdm.senderId, skdm);
  }

  pick(groupId: string, senderId: string): SerializedSKDM {
    const skdm = this.store.get(groupId)?.get(senderId);
    if (!skdm) throw new Error(`No SKDM from ${senderId} in group ${groupId}`);
    return skdm;
  }
}

describe('Group messaging (Sender Keys)', () => {
  let mailbox: SKDMMailbox;

  beforeEach(() => {
    mailbox = new SKDMMailbox();
  });

  /** Helper: Alice creates a sender key, publishes the SKDM, and Bob imports it. */
  async function aliceSendsSKDMToBob(groupId: string): Promise<void> {
    await alice.setupSenderKey(groupId);
    const skdm = await alice.getSenderKeyDistribution(groupId);
    await bob.processSenderKeyDistribution(groupId, 'alice', skdm);
  }

  it('setupSenderKey stores a valid single-state sender key record', async () => {
    await alice.setupSenderKey('group1');
    const raw = await aliceStore.loadSenderKey('group1', 'alice');
    expect(raw).toBeDefined();
    const record = JSON.parse(raw!);
    expect(record.version).toBe(1);
    expect(record.states).toHaveLength(1);
    const state = record.states[0];
    expect(state.iteration).toBe(0);
    expect(state.chainKey).toBeTypeOf('string');
    expect(state.distributionId).toBeTypeOf('string');
    expect(state.signingPublicKey).toBeTypeOf('string');
    expect(state.signingPrivateKey).toBeTypeOf('string');
  });

  it('getSenderKeyDistribution returns a verifiable SKDM', async () => {
    await alice.setupSenderKey('group1');
    const skdm = await alice.getSenderKeyDistribution('group1');
    expect(skdm.senderId).toBe('alice');
    expect(skdm.distributionId).toBeTypeOf('string');
    expect(skdm.iteration).toBe(0);
    expect(skdm.chainKey).toBeTypeOf('string');
    expect(skdm.signingPublicKey).toBeTypeOf('string');
    expect(skdm.signature).toBeTypeOf('string');
    const identity = await aliceStore.getIdentityKeyPair();
    expect(verifySKDM(skdm, identity!.ed.publicKey)).toBe(true);
  });

  it("processSenderKeyDistribution allows Bob to receive Alice's sender key", async () => {
    await alice.setupSenderKey('group1');
    const skdm = await alice.getSenderKeyDistribution('group1');
    await bob.processSenderKeyDistribution('group1', 'alice', skdm);

    const raw = await bobStore.loadSenderKey('group1', 'alice');
    expect(raw).toBeDefined();
    const record = JSON.parse(raw!);
    expect(record.states).toHaveLength(1);
    expect(record.states[0].distributionId).toBe(skdm.distributionId);
  });

  it('encryptGroupMessage and decryptGroupMessage round-trip between Alice and Bob', async () => {
    await aliceSendsSKDMToBob('group1');

    const msg = await alice.encryptGroupMessage('group1', 'hello group');
    expect(msg.senderId).toBe('alice');
    expect(msg.iteration).toBeTypeOf('number');
    expect(msg.ciphertext).toBeTypeOf('string');
    expect(msg.ciphertext).not.toContain('hello');

    const plaintext = await bob.decryptGroupMessage('group1', msg);
    expect(plaintext).toBe('hello group');
  });

  it("Bob cannot decrypt before receiving Alice's SKDM (no sender key yet)", async () => {
    await alice.setupSenderKey('group1');
    const msg = await alice.encryptGroupMessage('group1', 'secret');
    await expect(bob.decryptGroupMessage('group1', msg)).rejects.toThrow('No sender key');
  });

  it('rejects a forged SKDM', async () => {
    await alice.setupSenderKey('group1');
    const skdm = await alice.getSenderKeyDistribution('group1');
    const forged: SerializedSKDM = {
      ...skdm,
      chainKey: 'AA', // tampered payload that will not match the signature
    };
    await expect(
      bob.processSenderKeyDistribution('group1', 'alice', forged),
    ).rejects.toThrow('Invalid SKDM signature');
  });

  it('rotation: new chain used for new messages, old chain still decrypts in-flight ones', async () => {
    await aliceSendsSKDMToBob('group1');
    const before = await alice.encryptGroupMessage('group1', 'sent before rotation');

    // Rotate Alice's key and re-distribute to Bob.
    const newSkdm = await alice.rotateSenderKey('group1');
    await bob.processSenderKeyDistribution('group1', 'alice', newSkdm);

    const after = await alice.encryptGroupMessage('group1', 'sent after rotation');
    expect(after.distributionId).toBe(newSkdm.distributionId);
    expect(before.distributionId).not.toBe(newSkdm.distributionId);

    // Both decrypt: the record keeps the pre-rotation chain alive (transition).
    expect(await bob.decryptGroupMessage('group1', after)).toBe('sent after rotation');
    expect(await bob.decryptGroupMessage('group1', before)).toBe('sent before rotation');

    // Replay of the old-chain message is still rejected.
    await expect(bob.decryptGroupMessage('group1', before)).rejects.toThrow('already processed');
  });

  it('two independent groups do not interfere', async () => {
    await aliceSendsSKDMToBob('group1');
    await aliceSendsSKDMToBob('group2');

    const msg1 = await alice.encryptGroupMessage('group1', 'hello group1');
    const msg2 = await alice.encryptGroupMessage('group2', 'hello group2');

    expect(await bob.decryptGroupMessage('group1', msg1)).toBe('hello group1');
    expect(await bob.decryptGroupMessage('group2', msg2)).toBe('hello group2');

    // Cross-group: group1's record has no state for msg2's distributionId.
    await expect(bob.decryptGroupMessage('group1', msg2)).rejects.toThrow(
      'No sender key state for distribution',
    );
    await expect(bob.decryptGroupMessage('group2', msg1)).rejects.toThrow(
      'No sender key state for distribution',
    );
  });

  it('TOFU: rejects an SKDM claiming a sender whose identity is already pinned', async () => {
    // Bob pins Alice's real identity by processing her genuine SKDM first.
    await aliceSendsSKDMToBob('group1');

    // Mallory forges an SKDM claiming senderId "alice", signed by HER identity.
    const mallory = generateIdentityKeyPair();
    const forged = createSKDM(
      'alice',
      SenderKeyState.create(),
      mallory.ed.privateKey,
      mallory.ed.publicKey,
    );
    // The SKDM itself is internally valid (signed by its own identity key)…
    expect(verifySKDM(forged, mallory.ed.publicKey)).toBe(true);

    // …but Bob verifies against the PINNED identity for "alice" → rejected.
    await expect(
      bob.processSenderKeyDistribution('group1', 'alice', forged),
    ).rejects.toThrow('Invalid SKDM signature');

    // Alice's genuine chain is untouched.
    const msg = await alice.encryptGroupMessage('group1', 'still alice');
    expect(await bob.decryptGroupMessage('group1', msg)).toBe('still alice');
  });
});
