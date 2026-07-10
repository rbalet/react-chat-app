/**
 * Key generation helpers: registration id, signed prekeys, one-time prekeys.
 * Mirrors the role of libsignal's KeyHelper, implemented from the X3DH spec.
 */

import { encodePublicKey, generateDHKeyPair, randomBytes, sign } from '../core/crypto';
import { MAX_REGISTRATION_ID } from '../core/constants';
import type { IdentityKeyPair, OneTimePreKeyPair, SignedPreKeyPair } from '../core/types';

export { generateIdentityKeyPair } from './identity-key';

/** Random registration id in [1, MAX_REGISTRATION_ID] (rejection sampling). */
export function generateRegistrationId(): number {
  for (;;) {
    const bytes = randomBytes(2);
    const candidate = (((bytes[0]! << 8) | bytes[1]!) & 0x3fff) + 1;
    if (candidate <= MAX_REGISTRATION_ID) return candidate;
  }
}

/**
 * Generate a signed prekey: an X25519 pair whose Encode(publicKey) is
 * signed by the Ed25519 identity key (X3DH §3.1: SPK signature).
 */
export function generateSignedPreKey(identity: IdentityKeyPair, id: number): SignedPreKeyPair {
  const keyPair = generateDHKeyPair();
  const signature = sign(identity.ed.privateKey, encodePublicKey(keyPair.publicKey, 'x25519'));
  return { id, keyPair, signature, createdAt: Date.now() };
}

/** Generate `count` one-time prekeys with ids [startId, startId + count). */
export function generateOneTimePreKeys(startId: number, count: number): OneTimePreKeyPair[] {
  const out: OneTimePreKeyPair[] = [];
  for (let i = 0; i < count; i++) {
    out.push({ id: startId + i, keyPair: generateDHKeyPair() });
  }
  return out;
}
