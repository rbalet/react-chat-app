import { beforeEach, describe, expect, it } from 'vitest';
import { DoubleRatchet } from '../ratchet/ratchet';
import { generateDHKeyPair, randomBytes } from '../core/crypto';
import { bytesToUtf8, utf8ToBytes } from '../core/utils';
import type { KeyPair } from '../core/types';

let alice: DoubleRatchet;
let bob: DoubleRatchet;

beforeEach(() => {
  // Simulate the X3DH outcome: a shared secret + Bob's "signed prekey"
  // acting as his initial ratchet key.
  const sharedKey = randomBytes(32);
  const associatedData = randomBytes(66);
  const bobRatchetKey: KeyPair = generateDHKeyPair();
  alice = DoubleRatchet.initAlice(sharedKey, bobRatchetKey.publicKey, associatedData);
  bob = DoubleRatchet.initBob(sharedKey, bobRatchetKey, associatedData);
});

function send(from: DoubleRatchet, text: string): Uint8Array {
  return from.encrypt(utf8ToBytes(text));
}

function recv(to: DoubleRatchet, message: Uint8Array): string {
  return bytesToUtf8(to.decrypt(message));
}

describe('Double Ratchet', () => {
  it('ping-pong conversation across many DH ratchet steps', () => {
    for (let round = 0; round < 10; round++) {
      expect(recv(bob, send(alice, `alice ${round}`))).toBe(`alice ${round}`);
      expect(recv(alice, send(bob, `bob ${round}`))).toBe(`bob ${round}`);
    }
  });

  it('several messages in a row without a reply (single chain)', () => {
    const messages = [0, 1, 2, 3].map((i) => send(alice, `m${i}`));
    messages.forEach((message, i) => expect(recv(bob, message)).toBe(`m${i}`));
  });

  it('responder cannot send before receiving the first message', () => {
    expect(() => send(bob, 'too early')).toThrow(/sending chain/);
  });

  it('out-of-order delivery within one chain (skipped message keys)', () => {
    const m0 = send(alice, 'zero');
    const m1 = send(alice, 'one');
    const m2 = send(alice, 'two');
    expect(recv(bob, m2)).toBe('two');
    expect(recv(bob, m0)).toBe('zero');
    expect(recv(bob, m1)).toBe('one');
  });

  it('out-of-order delivery across DH ratchet steps', () => {
    const late = send(alice, 'sent early, arrives late');
    expect(recv(bob, send(alice, 'on time'))).toBe('on time');
    // Full round-trip ratchets both sides twice.
    expect(recv(alice, send(bob, 'reply'))).toBe('reply');
    expect(recv(bob, send(alice, 'newer chain'))).toBe('newer chain');
    // The old-chain message still decrypts from the stored skipped key.
    expect(recv(bob, late)).toBe('sent early, arrives late');
  });

  it('skipped message keys are one-shot (replay is rejected)', () => {
    const m0 = send(alice, 'zero');
    expect(recv(bob, send(alice, 'one'))).toBe('one'); // skips m0
    expect(recv(bob, m0)).toBe('zero');
    expect(() => recv(bob, m0)).toThrow();
  });

  it('rejects tampered messages and leaves the ratchet usable', () => {
    const good = send(alice, 'good');
    const tampered = good.slice();
    tampered[tampered.length - 1]! ^= 0xff;
    expect(() => recv(bob, tampered)).toThrow();
    // State was rolled back: the legitimate message still decrypts.
    expect(recv(bob, good)).toBe('good');
  });

  it('rejects messages when associated data differs (session binding)', () => {
    const sharedKey = randomBytes(32);
    const bobKey = generateDHKeyPair();
    const aliceAd = DoubleRatchet.initAlice(sharedKey, bobKey.publicKey, utf8ToBytes('AD-1'));
    const bobAd = DoubleRatchet.initBob(sharedKey, bobKey, utf8ToBytes('AD-2'));
    expect(() => recv(bobAd, send(aliceAd, 'cross-session'))).toThrow();
  });

  it('enforces MAX_SKIP', () => {
    for (let i = 0; i < 1001; i++) send(alice, `filler ${i}`);
    const tooFar = send(alice, 'message 1001');
    expect(() => recv(bob, tooFar)).toThrow(/skipped/);
  });

  it('survives serialization mid-conversation', () => {
    expect(recv(bob, send(alice, 'before'))).toBe('before');
    const alice2 = DoubleRatchet.deserialize(alice.serialize());
    const bob2 = DoubleRatchet.deserialize(bob.serialize());
    expect(recv(alice2, send(bob2, 'after restore'))).toBe('after restore');
    expect(recv(bob2, send(alice2, 'both ways'))).toBe('both ways');
  });

  it('provides forward secrecy across ratchet steps: keys differ every message', () => {
    // Indirect check: identical plaintexts never produce identical ciphertexts,
    // and old messages replayed to the CURRENT state are rejected once consumed.
    const c1 = send(alice, 'same');
    const c2 = send(alice, 'same');
    expect(c1).not.toEqual(c2);
    expect(recv(bob, c1)).toBe('same');
    expect(() => recv(bob, c1)).toThrow();
  });
});
