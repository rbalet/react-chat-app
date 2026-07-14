/**
 * Storage contract for the protocol. All methods are async so real
 * implementations can sit on IndexedDB, SQLite, encrypted storage, etc.
 * (the in-memory implementation is for tests and the PoC).
 *
 * Everything stored here is SECRET material except the identity public
 * halves — implementations must treat the store as sensitive.
 */

import type { IdentityKeyPair, OneTimePreKeyPair, SignedPreKeyPair } from '../core/types';

export interface SignalProtocolStore {
  // --- Local identity -----------------------------------------------------
  getIdentityKeyPair(): Promise<IdentityKeyPair | undefined>;
  storeIdentityKeyPair(keyPair: IdentityKeyPair): Promise<void>;
  getLocalRegistrationId(): Promise<number | undefined>;
  storeLocalRegistrationId(registrationId: number): Promise<void>;

  // --- Remote identities (trust store, TOFU) -------------------------------
  /** Stored Ed25519 public identity of a peer, if seen before. */
  getRemoteIdentity(userId: string): Promise<Uint8Array | undefined>;
  /**
   * Record a peer identity. Returns true if it REPLACED a different key
   * (the caller decides how to surface the safety-number change).
   */
  saveRemoteIdentity(userId: string, identityKeyEd: Uint8Array): Promise<boolean>;
  /** Trust-on-first-use check: unknown keys are trusted, changed keys are not. */
  isTrustedIdentity(userId: string, identityKeyEd: Uint8Array): Promise<boolean>;

  // --- Prekeys --------------------------------------------------------------
  storeSignedPreKey(signedPreKey: SignedPreKeyPair): Promise<void>;
  loadSignedPreKey(id: number): Promise<SignedPreKeyPair | undefined>;
  storeOneTimePreKey(preKey: OneTimePreKeyPair): Promise<void>;
  loadOneTimePreKey(id: number): Promise<OneTimePreKeyPair | undefined>;
  /** One-time prekeys are consumed after a successful X3DH (X3DH §3.4). */
  removeOneTimePreKey(id: number): Promise<void>;

  // --- Sessions ---------------------------------------------------------------
  /** Opaque serialized session record (see session/session-record.ts). */
  storeSession(userId: string, record: string): Promise<void>;
  loadSession(userId: string): Promise<string | undefined>;
  removeSession(userId: string): Promise<void>;

  // --- Sender Keys (groups) ---------------------------------------------------
  /** Serialized SenderKeyRecord JSON (multi-state) keyed by (groupId, senderId). */
  storeSenderKey(groupId: string, senderId: string, state: string): Promise<void>;
  loadSenderKey(groupId: string, senderId: string): Promise<string | undefined>;
}
