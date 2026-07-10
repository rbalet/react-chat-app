/**
 * Shared type definitions for the signal-protocol module.
 *
 * Implemented from the public-domain X3DH and Double Ratchet
 * specifications (https://signal.org/docs/). Apache-2.0.
 */

/** An asymmetric key pair (X25519 or Ed25519), raw 32-byte keys. */
export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Identity key pair. The long-term identity is an Ed25519 signing key;
 * its X25519 (Montgomery) form — used for the X3DH DH computations — is
 * derived once at generation time (birational map, RFC 7748 §4.1).
 */
export interface IdentityKeyPair {
  /** Ed25519 signing pair. The public half is the published identity. */
  ed: KeyPair;
  /** X25519 pair converted from `ed`, used for DH. */
  x: KeyPair;
}

/** A signed prekey (X3DH SPK): X25519 pair + Ed25519 signature by the identity key. */
export interface SignedPreKeyPair {
  id: number;
  keyPair: KeyPair;
  /** Ed25519 signature over Encode(publicKey) — see core/crypto.ts encodePublicKey. */
  signature: Uint8Array;
  /** Unix ms timestamp, for rotation policy. */
  createdAt: number;
}

/** A one-time prekey (X3DH OPK). */
export interface OneTimePreKeyPair {
  id: number;
  keyPair: KeyPair;
}

/** The public bundle Alice fetches from the server to start a session (X3DH §3.2). */
export interface PreKeyBundle {
  registrationId: number;
  /** Ed25519 public identity key (32 bytes). */
  identityKey: Uint8Array;
  signedPreKey: {
    id: number;
    publicKey: Uint8Array;
    signature: Uint8Array;
  };
  /** Optional: the server may have run out (X3DH allows omission). */
  oneTimePreKey?: {
    id: number;
    publicKey: Uint8Array;
  };
}

/** Wire envelope types. */
export enum MessageType {
  /** First message(s) of a session: carries the X3DH handshake data. */
  PreKey = 1,
  /** Regular Double Ratchet message. */
  Signal = 2,
}

/** JSON-safe encrypted message envelope (body is base64). */
export interface EncryptedMessage {
  type: MessageType;
  body: string;
}
