/**
 * Thin wrappers around @noble primitives — the ONLY file that imports
 * @noble directly. Everything above works with these named operations,
 * which keeps the mapping to the specs auditable in one place.
 *
 * Primitive choices (BRIEF.md §6):
 *  - DH:        X25519 (RFC 7748)
 *  - Signature: Ed25519 (RFC 8032), identity key converted to Montgomery for DH
 *  - KDF:       HKDF-SHA256 / HMAC-SHA256
 *  - AEAD:      AES-256-GCM-SIV (RFC 8452) — misuse-resistant, NOT plain GCM
 */

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcmsiv } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/ciphers/utils.js';

import { KEY_TYPE_ED25519, KEY_TYPE_X25519 } from './constants';
import { concatBytes } from './utils';
import type { KeyPair } from './types';

export { randomBytes };

export const AEAD_KEY_LENGTH = 32;
export const AEAD_NONCE_LENGTH = 12;

/** Generate an X25519 key pair (DH — ratchet keys, prekeys, ephemeral keys). */
export function generateDHKeyPair(): KeyPair {
  const { secretKey, publicKey } = x25519.keygen();
  return { publicKey, privateKey: secretKey };
}

/** X25519 shared secret. @noble rejects low-order public keys (all-zero output). */
export function dh(ourPrivateKey: Uint8Array, theirPublicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(ourPrivateKey, theirPublicKey);
}

/** Generate an Ed25519 signing key pair (identity keys). */
export function generateSigningKeyPair(): KeyPair {
  const { secretKey, publicKey } = ed25519.keygen();
  return { publicKey, privateKey: secretKey };
}

export function sign(privateKeyEd: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKeyEd);
}

export function verify(publicKeyEd: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKeyEd);
  } catch {
    // Malformed signature/key encodings must verify as false, not throw.
    return false;
  }
}

/** Edwards → Montgomery conversion of an Ed25519 PUBLIC key (RFC 7748 birational map). */
export function edPublicToX(publicKeyEd: Uint8Array): Uint8Array {
  return ed25519.utils.toMontgomery(publicKeyEd);
}

/** Edwards → Montgomery conversion of an Ed25519 SECRET key. */
export function edPrivateToX(privateKeyEd: Uint8Array): Uint8Array {
  return ed25519.utils.toMontgomerySecret(privateKeyEd);
}

export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return hkdf(sha256, ikm, salt, info, length);
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

/** AES-256-GCM-SIV encrypt. Output = ciphertext || 16-byte tag. */
export function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array {
  return gcmsiv(key, nonce, associatedData).encrypt(plaintext);
}

/** AES-256-GCM-SIV decrypt. Throws on authentication failure. */
export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array {
  return gcmsiv(key, nonce, associatedData).decrypt(ciphertext);
}

/**
 * Encode(PK) — public key wire encoding (X3DH §2.5): a single key-type
 * byte followed by the raw 32-byte key. Used for signed-prekey signatures
 * and for the X3DH associated data AD.
 */
export function encodePublicKey(publicKey: Uint8Array, type: 'x25519' | 'ed25519'): Uint8Array {
  if (publicKey.length !== 32) throw new Error('Public key must be 32 bytes');
  const typeByte = type === 'x25519' ? KEY_TYPE_X25519 : KEY_TYPE_ED25519;
  return concatBytes(new Uint8Array([typeByte]), publicKey);
}
