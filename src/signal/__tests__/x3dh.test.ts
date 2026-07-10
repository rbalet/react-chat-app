import { describe, expect, it } from 'vitest';
import { generateIdentityKeyPair } from '../identity/identity-key';
import { generateOneTimePreKeys, generateSignedPreKey } from '../identity/key-helper';
import { x3dhInitiate } from '../x3dh/initiator';
import { x3dhRespond } from '../x3dh/responder';
import type { PreKeyBundle } from '../core/types';

function makeBob() {
  const identity = generateIdentityKeyPair();
  const signedPreKey = generateSignedPreKey(identity, 1);
  const [oneTimePreKey] = generateOneTimePreKeys(1, 1);
  const bundle: PreKeyBundle = {
    registrationId: 42,
    identityKey: identity.ed.publicKey,
    signedPreKey: {
      id: signedPreKey.id,
      publicKey: signedPreKey.keyPair.publicKey,
      signature: signedPreKey.signature,
    },
    oneTimePreKey: { id: oneTimePreKey!.id, publicKey: oneTimePreKey!.keyPair.publicKey },
  };
  return { identity, signedPreKey, oneTimePreKey: oneTimePreKey!, bundle };
}

describe('X3DH key agreement', () => {
  it('initiator and responder derive the same SK and AD (with one-time prekey)', () => {
    const alice = generateIdentityKeyPair();
    const bob = makeBob();

    const aliceResult = x3dhInitiate(alice, bob.bundle);
    const bobResult = x3dhRespond(
      bob.identity,
      bob.signedPreKey.keyPair,
      bob.oneTimePreKey.keyPair,
      alice.ed.publicKey,
      aliceResult.ephemeralKey.publicKey,
    );

    expect(aliceResult.sharedKey).toEqual(bobResult.sharedKey);
    expect(aliceResult.sharedKey.length).toBe(32);
    expect(aliceResult.associatedData).toEqual(bobResult.associatedData);
  });

  it('works without a one-time prekey (server ran out) and yields a different SK', () => {
    const alice = generateIdentityKeyPair();
    const bob = makeBob();
    const { oneTimePreKey: _omitted, ...bundleWithout } = bob.bundle;

    const withOpk = x3dhInitiate(alice, bob.bundle);
    const withoutOpk = x3dhInitiate(alice, bundleWithout);
    const bobWithout = x3dhRespond(
      bob.identity,
      bob.signedPreKey.keyPair,
      undefined,
      alice.ed.publicKey,
      withoutOpk.ephemeralKey.publicKey,
    );

    expect(withoutOpk.sharedKey).toEqual(bobWithout.sharedKey);
    expect(withoutOpk.sharedKey).not.toEqual(withOpk.sharedKey);
  });

  it('rejects a bundle whose signed prekey signature is invalid', () => {
    const alice = generateIdentityKeyPair();
    const bob = makeBob();
    const forged = bob.bundle.signedPreKey.signature.slice();
    forged[0]! ^= 0x01;
    const badBundle: PreKeyBundle = {
      ...bob.bundle,
      signedPreKey: { ...bob.bundle.signedPreKey, signature: forged },
    };
    expect(() => x3dhInitiate(alice, badBundle)).toThrow(/signature/);
  });

  it('rejects a signed prekey signed by a different identity (MITM substitution)', () => {
    const alice = generateIdentityKeyPair();
    const bob = makeBob();
    const mallory = makeBob();
    const substituted: PreKeyBundle = {
      ...bob.bundle,
      // Mallory swaps in her own signed prekey; Bob's identity did not sign it.
      signedPreKey: mallory.bundle.signedPreKey,
    };
    expect(() => x3dhInitiate(alice, substituted)).toThrow(/signature/);
  });

  it('two sessions with the same bundle produce different secrets (fresh EK)', () => {
    const alice = generateIdentityKeyPair();
    const bob = makeBob();
    const first = x3dhInitiate(alice, bob.bundle);
    const second = x3dhInitiate(alice, bob.bundle);
    expect(first.sharedKey).not.toEqual(second.sharedKey);
  });
});
