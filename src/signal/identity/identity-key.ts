/**
 * Identity key management.
 *
 * The long-term identity is an Ed25519 key pair. The published identity is
 * the Ed25519 public key; peers convert it to X25519 (Montgomery) when they
 * need it for X3DH DH computations. Our own X25519 form is derived once and
 * kept alongside (this replaces XEdDSA, as libsignal does in practice).
 */

import { edPrivateToX, edPublicToX, generateSigningKeyPair } from '../core/crypto';
import type { IdentityKeyPair, KeyPair } from '../core/types';

export function generateIdentityKeyPair(): IdentityKeyPair {
  const ed = generateSigningKeyPair();
  return { ed, x: identityDHKeyPair(ed) };
}

/** Derive the X25519 (DH) form of an Ed25519 identity pair. */
export function identityDHKeyPair(ed: KeyPair): KeyPair {
  const privateKey = edPrivateToX(ed.privateKey);
  const publicKey = edPublicToX(ed.publicKey);
  return { publicKey, privateKey };
}

/** Convert a peer's published (Ed25519) identity to its DH (X25519) form. */
export function identityDHPublicKey(identityKeyEd: Uint8Array): Uint8Array {
  return edPublicToX(identityKeyEd);
}
