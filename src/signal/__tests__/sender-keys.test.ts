import { beforeEach, describe, expect, it } from 'vitest';

import { utf8ToBytes, bytesToBase64, base64ToBytes } from '../core/utils';
import { generateSigningKeyPair } from '../core/crypto';
import { InMemorySignalProtocolStore } from '../store/in-memory-store';
import { SenderKeyState } from '../sender-keys/sender-key-state';
import {
  createSKDM,
  verifySKDM,
  type SerializedSKDM,
} from '../sender-keys/sender-key-distribution';
import { GroupCipher } from '../sender-keys/group-cipher';

// ---------------------------------------------------------------------------
// SenderKeyState
// ---------------------------------------------------------------------------

describe('SenderKeyState', () => {
  describe('creation', () => {
    it('creates a state with a 32-byte non-zero chain key', () => {
      const state = SenderKeyState.create();
      expect(state.chainKey).toBeInstanceOf(Uint8Array);
      expect(state.chainKey.length).toBe(32);
      expect(state.chainKey.some((b) => b !== 0)).toBe(true);
    });

    it('creates a state with valid Ed25519 signing key pair', () => {
      const state = SenderKeyState.create();
      expect(state.signingKey.publicKey.length).toBe(32);
      expect(state.signingKey.privateKey.length).toBe(32);
      // Keys must differ (public != private in Ed25519).
      expect(state.signingKey.publicKey).not.toEqual(state.signingKey.privateKey);
    });

    it('creates a state with a non-empty distributionId', () => {
      const state = SenderKeyState.create();
      expect(state.distributionId).toBeTypeOf('string');
      expect(state.distributionId.length).toBeGreaterThan(0);
    });
  });

  describe('advance', () => {
    it('produces different key+nonce on consecutive calls', () => {
      const state = SenderKeyState.create();
      const p1 = state.advance();
      const p2 = state.advance();

      expect(p1.params.key).not.toEqual(p2.params.key);
      expect(p1.params.nonce).not.toEqual(p2.params.nonce);
    });

    it('mutates the chain key after each advance', () => {
      const state = SenderKeyState.create();
      const ck0 = state.chainKey.slice();
      state.advance();
      expect(state.chainKey).not.toEqual(ck0);

      const ck1 = state.chainKey.slice();
      state.advance();
      expect(state.chainKey).not.toEqual(ck1);
    });
  });

  describe('serialize / deserialize round-trip', () => {
    it('after round-trip, advance yields the same key+nonce', () => {
      const original = SenderKeyState.create();
      const serialized = original.serialize();
      const restored = SenderKeyState.deserialize(serialized);

      const origResult = original.advance();
      const restResult = restored.advance();

      expect(restResult.params.key).toEqual(origResult.params.key);
      expect(restResult.params.nonce).toEqual(origResult.params.nonce);
    });

    it('preserves the distributionId across round-trip', () => {
      const original = SenderKeyState.create();
      const restored = SenderKeyState.deserialize(original.serialize());
      expect(restored.distributionId).toBe(original.distributionId);
    });

    it('preserves the signing key across round-trip', () => {
      const original = SenderKeyState.create();
      const restored = SenderKeyState.deserialize(original.serialize());
      expect(restored.signingKey.publicKey).toEqual(original.signingKey.publicKey);
      expect(restored.signingKey.privateKey).toEqual(original.signingKey.privateKey);
    });
  });
});

// ---------------------------------------------------------------------------
// SenderKeyDistributionMessage
// ---------------------------------------------------------------------------

describe('SenderKeyDistributionMessage', () => {
  describe('createSKDM', () => {
    it('produces a valid SKDM with all required fields', () => {
      const state = SenderKeyState.create();
      const identity = generateSigningKeyPair();
      const skdm = createSKDM('alice', state, identity.privateKey, identity.publicKey);

      expect(skdm.senderId).toBe('alice');
      expect(skdm.distributionId).toBe(state.distributionId);
      expect(skdm.chainKey).toBeTypeOf('string');
      expect(base64ToBytes(skdm.chainKey)).toEqual(state.chainKey);
      expect(skdm.signingPublicKey).toBeTypeOf('string');
      expect(base64ToBytes(skdm.signingPublicKey)).toEqual(state.signingKey.publicKey);
      expect(skdm.signature).toBeTypeOf('string');
      expect(skdm.signature.length).toBeGreaterThan(0);
    });
  });

  describe('verifySKDM', () => {
    it('returns true for a valid SKDM', () => {
      const state = SenderKeyState.create();
      const identity = generateSigningKeyPair();
      const skdm = createSKDM('alice', state, identity.privateKey, identity.publicKey);
      expect(verifySKDM(skdm, identity.publicKey)).toBe(true);
    });

    it('returns false for an SKDM with a tampered chainKey byte', () => {
      const state = SenderKeyState.create();
      const identity = generateSigningKeyPair();
      const skdm = createSKDM('alice', state, identity.privateKey, identity.publicKey);

      const ck = base64ToBytes(skdm.chainKey);
      ck[0]! ^= 0x01;
      const tampered: SerializedSKDM = { ...skdm, chainKey: bytesToBase64(ck) };

      expect(verifySKDM(tampered, identity.publicKey)).toBe(false);
    });

    it('returns false for an SKDM signed by a different key (wrong-signer)', () => {
      const state = SenderKeyState.create();
      const identityA = generateSigningKeyPair();
      const identityB = generateSigningKeyPair();
      const skdm = createSKDM('alice', state, identityA.privateKey, identityA.publicKey);

      expect(verifySKDM(skdm, identityB.publicKey)).toBe(false);
    });

    it('returns false when the distributionId is tampered', () => {
      const state = SenderKeyState.create();
      const identity = generateSigningKeyPair();
      const skdm = createSKDM('alice', state, identity.privateKey, identity.publicKey);
      const tampered: SerializedSKDM = { ...skdm, distributionId: skdm.distributionId + 'X' };
      expect(verifySKDM(tampered, identity.publicKey)).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// GroupCipher
// ---------------------------------------------------------------------------

describe('GroupCipher', () => {
  const GROUP_ID = 'test-group-42';
  let store: InMemorySignalProtocolStore;
  let cipher: GroupCipher;

  beforeEach(() => {
    store = new InMemorySignalProtocolStore();
    cipher = new GroupCipher(store, GROUP_ID);
  });

  describe('encrypt / decrypt', () => {
    it('encrypts and decrypts a message end-to-end', async () => {
      const aliceStore = new InMemorySignalProtocolStore();
      const bobStore = new InMemorySignalProtocolStore();
      const aliceCipher = new GroupCipher(aliceStore, GROUP_ID);
      const bobCipher = new GroupCipher(bobStore, GROUP_ID);

      const identity = generateSigningKeyPair();

      const skdm = await aliceCipher.rotate('alice', identity.privateKey, identity.publicKey);
      await bobCipher.processDistributionMessage('alice', skdm, identity.publicKey);

      const plaintext = 'hello group from alice';
      const message = await aliceCipher.encrypt('alice', plaintext);

      expect(message.senderId).toBe('alice');
      expect(message.ciphertext).toBeTypeOf('string');
      expect(message.ciphertext).not.toContain(plaintext);
      expect(message.distributionId).toBeTypeOf('string');

      const decrypted = await bobCipher.decrypt(message);
      expect(decrypted).toBe(plaintext);
    });

    it('preserves multi-byte UTF-8 content through encrypt/decrypt', async () => {
      const aliceStore = new InMemorySignalProtocolStore();
      const bobStore = new InMemorySignalProtocolStore();
      const aliceCipher = new GroupCipher(aliceStore, GROUP_ID);
      const bobCipher = new GroupCipher(bobStore, GROUP_ID);

      const identity = generateSigningKeyPair();

      const skdm = await aliceCipher.rotate('alice', identity.privateKey, identity.publicKey);
      await bobCipher.processDistributionMessage('alice', skdm, identity.publicKey);

      const plaintext = 'héllo こんにちは 🚀✨';
      const message = await aliceCipher.encrypt('alice', plaintext);
      const decrypted = await bobCipher.decrypt(message);
      expect(decrypted).toBe(plaintext);
    });
  });

  describe('tamper rejection', () => {
    it('throws when a ciphertext byte is flipped', async () => {
      const aliceStore = new InMemorySignalProtocolStore();
      const bobStore = new InMemorySignalProtocolStore();
      const aliceCipher = new GroupCipher(aliceStore, GROUP_ID);
      const bobCipher = new GroupCipher(bobStore, GROUP_ID);

      const identity = generateSigningKeyPair();

      const skdm = await aliceCipher.rotate('alice', identity.privateKey, identity.publicKey);
      await bobCipher.processDistributionMessage('alice', skdm, identity.publicKey);

      const message = await aliceCipher.encrypt('alice', 'top secret');

      const raw = base64ToBytes(message.ciphertext);
      raw[0]! ^= 0x01;
      const tamperedMessage = { ...message, ciphertext: bytesToBase64(raw) };

      await expect(bobCipher.decrypt(tamperedMessage)).rejects.toThrow();
    });

    it('state is not corrupted after a failed decrypt (rollback)', async () => {
      const aliceStore = new InMemorySignalProtocolStore();
      const bobStore = new InMemorySignalProtocolStore();
      const aliceCipher = new GroupCipher(aliceStore, GROUP_ID);
      const bobCipher = new GroupCipher(bobStore, GROUP_ID);

      const identity = generateSigningKeyPair();

      const skdm = await aliceCipher.rotate('alice', identity.privateKey, identity.publicKey);
      await bobCipher.processDistributionMessage('alice', skdm, identity.publicKey);

      const message = await aliceCipher.encrypt('alice', 'msg1');
      const raw = base64ToBytes(message.ciphertext);
      raw[0]! ^= 0x01;
      const tampered = { ...message, ciphertext: bytesToBase64(raw) };

      await expect(bobCipher.decrypt(tampered)).rejects.toThrow();

      // The legitimate message should still decrypt after the failed attempt —
      // the rollback prevented the chain from skipping a step.
      const decrypted = await bobCipher.decrypt(message);
      expect(decrypted).toBe('msg1');
    });

    it('throws when associated data is wrong (different group)', async () => {
      const aliceStore = new InMemorySignalProtocolStore();
      const bobStore = new InMemorySignalProtocolStore();
      const aliceCipher = new GroupCipher(aliceStore, GROUP_ID);
      const wrongCipher = new GroupCipher(bobStore, 'wrong-group');

      const identity = generateSigningKeyPair();

      const skdm = await aliceCipher.rotate('alice', identity.privateKey, identity.publicKey);
      await wrongCipher.processDistributionMessage('alice', skdm, identity.publicKey);

      const message = await aliceCipher.encrypt('alice', 'test');

      // wrongCipher has the correct state but a different groupId —
      // the AEAD associated data mismatch causes the decrypt to fail.
      await expect(wrongCipher.decrypt(message)).rejects.toThrow();
    });
  });

  describe('stale distribution', () => {
    it('rejects messages with an old distributionId after rotation', async () => {
      const identity = generateSigningKeyPair();

      // Alice's first key — rotate stores the state and returns the SKDM.
      await cipher.rotate('alice', identity.privateKey, identity.publicKey);
      const msg = await cipher.encrypt('alice', 'under key v1');

      // Rotate again — stores a fresh state with a new distributionId,
      // replacing the previous one in the store.
      await cipher.rotate('alice', identity.privateKey, identity.publicKey);

      // The old message carries distributionId v1; the store now has v2.
      await expect(cipher.decrypt(msg)).rejects.toThrow('Distribution mismatch');
    });
  });

  describe('chain advancement', () => {
    it('decrypts 3 consecutive messages in order', async () => {
      const aliceStore = new InMemorySignalProtocolStore();
      const bobStore = new InMemorySignalProtocolStore();
      const aliceCipher = new GroupCipher(aliceStore, GROUP_ID);
      const bobCipher = new GroupCipher(bobStore, GROUP_ID);

      const identity = generateSigningKeyPair();

      const skdm = await aliceCipher.rotate('alice', identity.privateKey, identity.publicKey);
      await bobCipher.processDistributionMessage('alice', skdm, identity.publicKey);

      const messages = [
        await aliceCipher.encrypt('alice', 'msg-0'),
        await aliceCipher.encrypt('alice', 'msg-1'),
        await aliceCipher.encrypt('alice', 'msg-2'),
      ];

      expect(await bobCipher.decrypt(messages[0]!)).toBe('msg-0');
      expect(await bobCipher.decrypt(messages[1]!)).toBe('msg-1');
      expect(await bobCipher.decrypt(messages[2]!)).toBe('msg-2');
    });

    it('rejects messages whose iteration is behind the current chain', async () => {
      const aliceStore = new InMemorySignalProtocolStore();
      const bobStore = new InMemorySignalProtocolStore();
      const aliceCipher = new GroupCipher(aliceStore, GROUP_ID);
      const bobCipher = new GroupCipher(bobStore, GROUP_ID);

      const identity = generateSigningKeyPair();

      const skdm = await aliceCipher.rotate('alice', identity.privateKey, identity.publicKey);
      await bobCipher.processDistributionMessage('alice', skdm, identity.publicKey);

      const m0 = await aliceCipher.encrypt('alice', 'zero');
      const m1 = await aliceCipher.encrypt('alice', 'one');

      // m1 arrives first — the chain fast-forwards to match its iteration.
      expect(await bobCipher.decrypt(m1)).toBe('one');

      // m0 is now behind the chain (already skipped) and is rejected.
      await expect(bobCipher.decrypt(m0)).rejects.toThrow();
    });
  });

  describe('two senders', () => {
    it('each sender key is stored and used independently', async () => {
      const aliceStore = new InMemorySignalProtocolStore();
      const bobStore = new InMemorySignalProtocolStore();
      const aliceCipher = new GroupCipher(aliceStore, GROUP_ID);
      const bobCipher = new GroupCipher(bobStore, GROUP_ID);

      const aliceIdentity = generateSigningKeyPair();
      const bobIdentity = generateSigningKeyPair();

      // Both create their own sender keys.
      const aliceSkdm = await aliceCipher.rotate('alice', aliceIdentity.privateKey, aliceIdentity.publicKey);
      const bobSkdm = await bobCipher.rotate('bob', bobIdentity.privateKey, bobIdentity.publicKey);

      // Cross-process the distribution messages.
      await aliceCipher.processDistributionMessage('bob', bobSkdm, bobIdentity.publicKey);
      await bobCipher.processDistributionMessage('alice', aliceSkdm, aliceIdentity.publicKey);

      // Alice → Bob.
      const msgFromAlice = await aliceCipher.encrypt('alice', 'alice says hi');
      expect(await bobCipher.decrypt(msgFromAlice)).toBe('alice says hi');

      // Bob → Alice.
      const msgFromBob = await bobCipher.encrypt('bob', 'bob replies');
      expect(await aliceCipher.decrypt(msgFromBob)).toBe('bob replies');

      // Both can send consecutive messages without interfering.
      const a2 = await aliceCipher.encrypt('alice', 'alice msg 2');
      const b2 = await bobCipher.encrypt('bob', 'bob msg 2');
      expect(await bobCipher.decrypt(a2)).toBe('alice msg 2');
      expect(await aliceCipher.decrypt(b2)).toBe('bob msg 2');
    });

    it('sender keys are isolated by senderId within the same store', async () => {
      const aliceState = SenderKeyState.create();
      const bobState = SenderKeyState.create();

      await store.storeSenderKey(GROUP_ID, 'alice', JSON.stringify(aliceState.serialize()));
      await store.storeSenderKey(GROUP_ID, 'bob', JSON.stringify(bobState.serialize()));

      const aliceRaw = await store.loadSenderKey(GROUP_ID, 'alice');
      const bobRaw = await store.loadSenderKey(GROUP_ID, 'bob');

      expect(aliceRaw).toBeDefined();
      expect(bobRaw).toBeDefined();
      expect(aliceRaw).not.toBe(bobRaw);

      const loadedAlice = SenderKeyState.deserialize(JSON.parse(aliceRaw!));
      const loadedBob = SenderKeyState.deserialize(JSON.parse(bobRaw!));

      expect(loadedAlice.chainKey).toEqual(aliceState.chainKey);
      expect(loadedBob.chainKey).toEqual(bobState.chainKey);
      expect(loadedAlice.distributionId).not.toBe(loadedBob.distributionId);
    });
  });

  describe('getDistributionMessage', () => {
    it('returns a verifiable SKDM for the current sender key state', async () => {
      const identity = generateSigningKeyPair();
      const skdm = await cipher.rotate('alice', identity.privateKey, identity.publicKey);
      // rotate already stored, so getDistributionMessage reads the fresh state.
      const dm2 = await cipher.getDistributionMessage('alice', identity.privateKey, identity.publicKey);
      expect(verifySKDM(dm2, identity.publicKey)).toBe(true);
      expect(dm2.senderId).toBe('alice');
    });

    it('throws when no sender key exists', async () => {
      const identity = generateSigningKeyPair();
      await expect(
        cipher.getDistributionMessage('nobody', identity.privateKey, identity.publicKey),
      ).rejects.toThrow();
    });
  });

  describe('processDistributionMessage', () => {
    it('rejects an unverified SKDM', async () => {
      const state = SenderKeyState.create();
      const identity = generateSigningKeyPair();
      const skdm = createSKDM('alice', state, identity.privateKey, identity.publicKey);

      const ck = base64ToBytes(skdm.chainKey);
      ck[0]! ^= 0x01;
      const bad: SerializedSKDM = { ...skdm, chainKey: bytesToBase64(ck) };

      await expect(
        cipher.processDistributionMessage('alice', bad, identity.publicKey),
      ).rejects.toThrow('Invalid SKDM signature');
    });

    it('stores the received state ready for decryption', async () => {
      const state = SenderKeyState.create();
      const identity = generateSigningKeyPair();
      const skdm = createSKDM('alice', state, identity.privateKey, identity.publicKey);
      await cipher.processDistributionMessage('alice', skdm, identity.publicKey);

      const raw = await store.loadSenderKey(GROUP_ID, 'alice');
      expect(raw).toBeDefined();
      const stored = SenderKeyState.deserialize(JSON.parse(raw!));
      expect(stored.chainKey).toEqual(state.chainKey);
      expect(stored.distributionId).toBe(state.distributionId);
      expect(stored.signingKey.publicKey).toEqual(state.signingKey.publicKey);
      // Only the public half of the signing key is stored for decryption.
      expect(stored.signingKey.privateKey).toEqual(new Uint8Array(0));
    });
  });

  describe('encrypt with no sender key', () => {
    it('throws when encrypting without setupSenderKey', async () => {
      await expect(cipher.encrypt('alice', 'no key stored')).rejects.toThrow(
        'No sender key for this group',
      );
    });
  });

  describe('decrypt with unknown sender', () => {
    it('throws when decrypting from an unknown sender', async () => {
      const fakeMessage = {
        ciphertext: bytesToBase64(new Uint8Array(32)),
        distributionId: 'does-not-exist',
        senderId: 'stranger',
        iteration: 0,
        signature: '',
      };
      await expect(cipher.decrypt(fakeMessage)).rejects.toThrow('No sender key');
    });
  });
});
