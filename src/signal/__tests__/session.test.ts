import { beforeEach, describe, expect, it } from 'vitest';
import { InMemorySignalProtocolStore } from '../store/in-memory-store';
import { SessionCipher } from '../session/session-cipher';
import { startSession } from '../session/session-builder';
import { parsePreKeyMessage, serializePreKeyMessage } from '../session/prekey-message';
import { base64ToBytes, bytesToBase64 } from '../core/utils';
import { generateIdentityKeyPair } from '../identity/identity-key';
import {
  generateOneTimePreKeys,
  generateRegistrationId,
  generateSignedPreKey,
} from '../identity/key-helper';
import { MessageType } from '../core/types';
import type { PreKeyBundle } from '../core/types';

interface Party {
  userId: string;
  store: InMemorySignalProtocolStore;
}

async function makeParty(userId: string): Promise<Party> {
  const store = new InMemorySignalProtocolStore();
  const identity = generateIdentityKeyPair();
  await store.storeIdentityKeyPair(identity);
  await store.storeLocalRegistrationId(generateRegistrationId());
  const signedPreKey = generateSignedPreKey(identity, 1);
  await store.storeSignedPreKey(signedPreKey);
  for (const preKey of generateOneTimePreKeys(1, 5)) await store.storeOneTimePreKey(preKey);
  return { userId, store };
}

/** What the key server would hand to Alice (consuming one-time prekey `opkId`). */
async function bundleOf(party: Party, opkId = 1): Promise<PreKeyBundle> {
  const identity = (await party.store.getIdentityKeyPair())!;
  const signedPreKey = (await party.store.loadSignedPreKey(1))!;
  const oneTimePreKey = (await party.store.loadOneTimePreKey(opkId))!;
  return {
    registrationId: (await party.store.getLocalRegistrationId())!,
    identityKey: identity.ed.publicKey,
    signedPreKey: {
      id: signedPreKey.id,
      publicKey: signedPreKey.keyPair.publicKey,
      signature: signedPreKey.signature,
    },
    oneTimePreKey: { id: oneTimePreKey.id, publicKey: oneTimePreKey.keyPair.publicKey },
  };
}

let alice: Party;
let bob: Party;

beforeEach(async () => {
  alice = await makeParty('alice');
  bob = await makeParty('bob');
});

describe('SessionCipher end-to-end', () => {
  it('establishes a session and exchanges messages, switching envelope types', async () => {
    await startSession(alice.store, bob.userId, await bundleOf(bob));
    const aliceCipher = new SessionCipher(alice.store, bob.userId);
    const bobCipher = new SessionCipher(bob.store, alice.userId);

    // Alice → Bob: first messages carry the handshake (PreKey envelopes).
    const first = await aliceCipher.encrypt('hello bob');
    const second = await aliceCipher.encrypt('still there?');
    expect(first.type).toBe(MessageType.PreKey);
    expect(second.type).toBe(MessageType.PreKey);
    expect(await bobCipher.decrypt(first)).toBe('hello bob');
    expect(await bobCipher.decrypt(second)).toBe('still there?');

    // Bob → Alice: regular envelope; on receipt Alice drops the handshake.
    const reply = await bobCipher.encrypt('hi alice');
    expect(reply.type).toBe(MessageType.Signal);
    expect(await aliceCipher.decrypt(reply)).toBe('hi alice');

    const third = await aliceCipher.encrypt('great');
    expect(third.type).toBe(MessageType.Signal);
    expect(await bobCipher.decrypt(third)).toBe('great');
  });

  it('consumes the one-time prekey exactly once, after successful decrypt', async () => {
    await startSession(alice.store, bob.userId, await bundleOf(bob, 3));
    const aliceCipher = new SessionCipher(alice.store, bob.userId);
    const bobCipher = new SessionCipher(bob.store, alice.userId);

    expect(await bob.store.loadOneTimePreKey(3)).toBeDefined();
    await bobCipher.decrypt(await aliceCipher.encrypt('consume opk 3'));
    expect(await bob.store.loadOneTimePreKey(3)).toBeUndefined();
  });

  it('handles duplicate delivery of the same prekey message idempotently', async () => {
    await startSession(alice.store, bob.userId, await bundleOf(bob));
    const aliceCipher = new SessionCipher(alice.store, bob.userId);
    const bobCipher = new SessionCipher(bob.store, alice.userId);

    const message = await aliceCipher.encrypt('dup');
    expect(await bobCipher.decrypt(message)).toBe('dup');
    // Same envelope again: same session (baseKey match), replay rejected by
    // the ratchet — but it must NOT fork a second session or crash on the
    // missing one-time prekey.
    await expect(bobCipher.decrypt(message)).rejects.toThrow();
    // Session still healthy afterwards.
    expect(await bobCipher.decrypt(await aliceCipher.encrypt('next'))).toBe('next');
  });

  it('a forged prekey message does not burn the one-time prekey', async () => {
    await startSession(alice.store, bob.userId, await bundleOf(bob, 2));
    const aliceCipher = new SessionCipher(alice.store, bob.userId);
    const bobCipher = new SessionCipher(bob.store, alice.userId);

    const genuine = await aliceCipher.encrypt('genuine');
    const forgedBytes = Buffer.from(genuine.body, 'base64');
    forgedBytes[forgedBytes.length - 1]! ^= 0xff; // corrupt the AEAD tag
    const forged = { ...genuine, body: forgedBytes.toString('base64') };

    await expect(bobCipher.decrypt(forged)).rejects.toThrow();
    expect(await bob.store.loadOneTimePreKey(2)).toBeDefined(); // not consumed
    expect(await bob.store.loadSession(alice.userId)).toBeUndefined(); // no session stored

    expect(await bobCipher.decrypt(genuine)).toBe('genuine'); // still works
  });

  it('rejects a session with a changed identity key (TOFU)', async () => {
    await startSession(alice.store, bob.userId, await bundleOf(bob));
    const aliceCipher = new SessionCipher(alice.store, bob.userId);
    await new SessionCipher(bob.store, alice.userId).decrypt(await aliceCipher.encrypt('hi'));

    // "Bob" reinstalls with a brand-new identity; Alice must refuse silently
    // re-keying to the imposter bundle.
    const impostor = await makeParty('bob');
    await expect(startSession(alice.store, bob.userId, await bundleOf(impostor))).rejects.toThrow(
      /[Uu]ntrusted/,
    );
  });

  it('out-of-order delivery works through the session layer', async () => {
    await startSession(alice.store, bob.userId, await bundleOf(bob));
    const aliceCipher = new SessionCipher(alice.store, bob.userId);
    const bobCipher = new SessionCipher(bob.store, alice.userId);

    const m0 = await aliceCipher.encrypt('zero');
    const m1 = await aliceCipher.encrypt('one');
    const m2 = await aliceCipher.encrypt('two');
    expect(await bobCipher.decrypt(m1)).toBe('one');
    expect(await bobCipher.decrypt(m2)).toBe('two');
    expect(await bobCipher.decrypt(m0)).toBe('zero');
  });

  it('encrypting without a session throws a clear error', async () => {
    await expect(new SessionCipher(alice.store, 'nobody').encrypt('x')).rejects.toThrow(
      /No session/,
    );
  });

  it('rejects a replayed prekey envelope with a substituted identity key', async () => {
    await startSession(alice.store, bob.userId, await bundleOf(bob));
    const aliceCipher = new SessionCipher(alice.store, bob.userId);
    const bobCipher = new SessionCipher(bob.store, alice.userId);

    const genuine = await aliceCipher.encrypt('genuine');
    expect(await bobCipher.decrypt(genuine)).toBe('genuine'); // pins Alice's identity

    // Mallory re-wraps Alice's envelope with her own identity key: the
    // baseKey fast-path must not match, and TOFU must reject it.
    const mallory = generateIdentityKeyPair();
    const parsed = parsePreKeyMessage(base64ToBytes(genuine.body));
    const forged = {
      ...genuine,
      body: bytesToBase64(
        serializePreKeyMessage({ ...parsed, identityKey: mallory.ed.publicKey }),
      ),
    };
    await expect(bobCipher.decrypt(forged)).rejects.toThrow(/[Uu]ntrusted/);

    // The genuine session is unharmed.
    expect(await bobCipher.decrypt(await aliceCipher.encrypt('still fine'))).toBe('still fine');
  });
});

describe('Concurrent mutual initiation (tie-break)', () => {
  it('converges on a single session; exactly one handshake survives', async () => {
    // Both sides initiate before seeing the other's handshake.
    await startSession(alice.store, bob.userId, await bundleOf(bob));
    await startSession(bob.store, alice.userId, await bundleOf(alice));
    const aliceCipher = new SessionCipher(alice.store, bob.userId);
    const bobCipher = new SessionCipher(bob.store, alice.userId);

    const fromAlice = await aliceCipher.encrypt('from alice');
    const fromBob = await bobCipher.encrypt('from bob');

    // Crosswise delivery. The LOWER X3DH base key wins on both sides, so
    // exactly one side accepts the peer's handshake (and becomes responder);
    // the other rejects it and keeps its own pending handshake.
    const aliceGot = await aliceCipher.decrypt(fromBob).then(
      (plaintext) => ({ ok: true as const, plaintext }),
      () => ({ ok: false as const }),
    );
    const bobGot = await bobCipher.decrypt(fromAlice).then(
      (plaintext) => ({ ok: true as const, plaintext }),
      () => ({ ok: false as const }),
    );
    expect(aliceGot.ok).not.toBe(bobGot.ok);

    // If Alice accepted, Bob's handshake won (and vice versa).
    const [winner, responder, deliveredText] = aliceGot.ok
      ? [bobCipher, aliceCipher, 'from bob']
      : [aliceCipher, bobCipher, 'from alice'];
    const accepted = aliceGot.ok ? aliceGot : bobGot;
    if (!accepted.ok) throw new Error('unreachable: exactly one side accepted');
    expect(accepted.plaintext).toBe(deliveredText);

    // The winner never received an authenticated inbound yet, so it keeps
    // attaching its handshake; the responder decrypts it via the duplicate
    // fast-path. The loser's first payload is lost — by design.
    const followUp = await winner.encrypt('follow-up');
    expect(followUp.type).toBe(MessageType.PreKey);
    expect(await responder.decrypt(followUp)).toBe('follow-up');

    const reply = await responder.encrypt('reply');
    expect(reply.type).toBe(MessageType.Signal);
    expect(await winner.decrypt(reply)).toBe('reply');

    // Fully converged: both directions now flow as regular Signal messages.
    const settled = await winner.encrypt('settled');
    expect(settled.type).toBe(MessageType.Signal);
    expect(await responder.decrypt(settled)).toBe('settled');
  });
});
