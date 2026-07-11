/**
 * @up4it/signal-protocol
 *
 * Clean-room TypeScript implementation of the Signal Protocol
 * (X3DH + Double Ratchet; Sender Keys in Phase 2), written solely from
 * the public-domain specifications at https://signal.org/docs/.
 *
 * Framework-agnostic and transport-agnostic: crypto comes exclusively
 * from @noble/curves, @noble/hashes and @noble/ciphers; the key server
 * is an injected interface. License: Apache-2.0 (LICENSE in this dir).
 */

import { generateOneTimePreKeys, generateRegistrationId, generateSignedPreKey } from './identity/key-helper';
import { generateIdentityKeyPair } from './identity/identity-key';
import { deserializePreKeyBundle, type SerializedPreKeyBundle } from './x3dh/prekey-bundle';
import { startSession } from './session/session-builder';
import { SessionCipher } from './session/session-cipher';
import { DEFAULT_PREKEY_BATCH_SIZE } from './core/constants';
import { base64ToBytes, bytesToBase64 } from './core/utils';
import type { EncryptedMessage } from './core/types';
import type { SignalProtocolStore } from './store/store-interface';
import { SenderKeyRecord } from './sender-keys/sender-key-record';
import { GroupCipher, type GroupMessage } from './sender-keys/group-cipher';
import type { SerializedSKDM } from './sender-keys/sender-key-distribution';

// ---------------------------------------------------------------------------
// Public re-exports
// ---------------------------------------------------------------------------

export { MessageType } from './core/types';
export type {
  EncryptedMessage,
  IdentityKeyPair,
  KeyPair,
  OneTimePreKeyPair,
  PreKeyBundle,
  SignedPreKeyPair,
} from './core/types';
export { InMemorySignalProtocolStore } from './store/in-memory-store';
export type { SignalProtocolStore } from './store/store-interface';
export { SessionCipher } from './session/session-cipher';
export { SessionRecord } from './session/session-record';
export { DoubleRatchet } from './ratchet/ratchet';
export { x3dhInitiate } from './x3dh/initiator';
export { x3dhRespond } from './x3dh/responder';
export {
  deserializePreKeyBundle,
  serializePreKeyBundle,
  type SerializedPreKeyBundle,
} from './x3dh/prekey-bundle';
export {
  generateIdentityKeyPair,
  generateOneTimePreKeys,
  generateRegistrationId,
  generateSignedPreKey,
} from './identity/key-helper';
export { GroupCipher } from './sender-keys/group-cipher';
export type { GroupMessage } from './sender-keys/group-cipher';
export type { SerializedSKDM } from './sender-keys/sender-key-distribution';

// ---------------------------------------------------------------------------
// Key server contract (implemented by the application, e.g. via axios/fetch)
// ---------------------------------------------------------------------------

/** Public key material uploaded at initialization. All bytes base64. */
export interface PublishedKeys {
  registrationId: number;
  identityKey: string;
  signedPreKey: {
    id: number;
    publicKey: string;
    signature: string;
  };
  oneTimePreKeys: {
    id: number;
    publicKey: string;
  }[];
}

export interface KeyServerClient {
  /** POST /keys/:userId */
  publishKeys(userId: string, keys: PublishedKeys): Promise<void>;
  /** GET /keys/:userId — server atomically consumes one one-time prekey. */
  fetchPreKeyBundle(userId: string): Promise<SerializedPreKeyBundle>;
}

// ---------------------------------------------------------------------------
// Facade
// ---------------------------------------------------------------------------

export class SignalProtocolManager {
  /**
   * Per-peer operation queues. Encrypt/decrypt are read-modify-write on the
   * stored session record with awaits in between: two interleaved calls for
   * the same peer would both start from the same state and the last write
   * would win — losing a chain advance and resurrecting an already-used
   * skipped message key (replay window). Serializing per peer removes the
   * interleaving (same role as libsignal's session lock).
   */
  private readonly sessionQueues = new Map<string, Promise<unknown>>();

  /** Per-group operation queues (same serialising pattern as sessions). */
  private readonly groupQueues = new Map<string, Promise<unknown>>();

  constructor(
    private readonly userId: string,
    private readonly store: SignalProtocolStore,
    private readonly server: KeyServerClient,
  ) {}

  private runExclusive<T>(remoteUserId: string, task: () => Promise<T>): Promise<T> {
    const previous = this.sessionQueues.get(remoteUserId) ?? Promise.resolve();
    // Run after the predecessor settles, whatever its outcome.
    const next = previous.then(task, task);
    this.sessionQueues.set(remoteUserId, next.catch(() => undefined));
    return next;
  }

  private runGroupExclusive<T>(groupId: string, task: () => Promise<T>): Promise<T> {
    const previous = this.groupQueues.get(groupId) ?? Promise.resolve();
    const next = previous.then(task, task);
    this.groupQueues.set(groupId, next.catch(() => undefined));
    return next;
  }

  /**
   * First-run bootstrap: generate the identity key pair, registration id,
   * signed prekey and a batch of one-time prekeys; store the private
   * halves and publish the public halves to the key server.
   * No-op if an identity already exists (rotation/replenishment come with
   * the backend integration).
   */
  async initialize(): Promise<void> {
    if (await this.store.getIdentityKeyPair()) return;

    const identity = generateIdentityKeyPair();
    const registrationId = generateRegistrationId();
    const signedPreKey = generateSignedPreKey(identity, 1);
    const oneTimePreKeys = generateOneTimePreKeys(1, DEFAULT_PREKEY_BATCH_SIZE);

    await this.store.storeIdentityKeyPair(identity);
    await this.store.storeLocalRegistrationId(registrationId);
    await this.store.storeSignedPreKey(signedPreKey);
    for (const preKey of oneTimePreKeys) {
      await this.store.storeOneTimePreKey(preKey);
    }

    await this.server.publishKeys(this.userId, {
      registrationId,
      identityKey: bytesToBase64(identity.ed.publicKey),
      signedPreKey: {
        id: signedPreKey.id,
        publicKey: bytesToBase64(signedPreKey.keyPair.publicKey),
        signature: bytesToBase64(signedPreKey.signature),
      },
      oneTimePreKeys: oneTimePreKeys.map((preKey) => ({
        id: preKey.id,
        publicKey: bytesToBase64(preKey.keyPair.publicKey),
      })),
    });
  }

  /**
   * Encrypt a message for a peer, establishing the session via X3DH
   * (bundle fetch) if none exists yet.
   */
  async encryptMessage(remoteUserId: string, plaintext: string): Promise<EncryptedMessage> {
    return this.runExclusive(remoteUserId, async () => {
      const cipher = new SessionCipher(this.store, remoteUserId);
      if (!(await cipher.hasSession())) {
        const bundle = deserializePreKeyBundle(await this.server.fetchPreKeyBundle(remoteUserId));
        await startSession(this.store, remoteUserId, bundle);
      }
      return cipher.encrypt(plaintext);
    });
  }

  /** Decrypt a message from a peer (bootstraps the session on prekey messages). */
  async decryptMessage(remoteUserId: string, message: EncryptedMessage): Promise<string> {
    return this.runExclusive(remoteUserId, () =>
      new SessionCipher(this.store, remoteUserId).decrypt(message),
    );
  }

  // ---------------------------------------------------------------------------
  // Group messaging (Sender Keys)
  // ---------------------------------------------------------------------------

  /** Create a fresh sender key record for this user in a group. */
  async setupSenderKey(groupId: string): Promise<void> {
    return this.runGroupExclusive(groupId, async () => {
      const record = SenderKeyRecord.create();
      await this.store.storeSenderKey(groupId, this.userId, JSON.stringify(record.serialize()));
    });
  }

  /** Get a SenderKeyDistributionMessage (SKDM) for this user's current key. */
  async getSenderKeyDistribution(groupId: string): Promise<SerializedSKDM> {
    return this.runGroupExclusive(groupId, async () => {
      const id = await this.store.getIdentityKeyPair();
      if (!id) throw new Error('No identity key — call initialize() first');
      const cipher = new GroupCipher(this.store, groupId);
      return cipher.getDistributionMessage(this.userId, id.ed.privateKey, id.ed.publicKey);
    });
  }

  /** Process an SKDM received from another sender — verifies the identity-key
   *  signature against the stored remote identity, then stores the sender key
   *  state for future group message decryption. */
  async processSenderKeyDistribution(
    groupId: string,
    senderId: string,
    skdm: SerializedSKDM,
  ): Promise<void> {
    return this.runGroupExclusive(groupId, async () => {
      // Fetch the sender's previously-stored identity public key (TOFU).
      // If unseen, trust-on-first-use: store it now from the SKDM payload.
      let identityKey = await this.store.getRemoteIdentity(senderId);
      if (!identityKey) {
        identityKey = base64ToBytes(skdm.identityKey);
        await this.store.saveRemoteIdentity(senderId, identityKey);
      }
      const cipher = new GroupCipher(this.store, groupId);
      return cipher.processDistributionMessage(senderId, skdm, identityKey);
    });
  }

  /** Encrypt a message for a group using this user's sender key. */
  async encryptGroupMessage(groupId: string, plaintext: string): Promise<GroupMessage> {
    return this.runGroupExclusive(groupId, async () => {
      const cipher = new GroupCipher(this.store, groupId);
      return cipher.encrypt(this.userId, plaintext);
    });
  }

  /** Decrypt a group message from another sender. */
  async decryptGroupMessage(groupId: string, message: GroupMessage): Promise<string> {
    return this.runGroupExclusive(groupId, async () => {
      const cipher = new GroupCipher(this.store, groupId);
      return cipher.decrypt(message);
    });
  }

  /** Rotate this user's sender key (e.g. on member departure) and return the
   *  new SKDM for redistribution to remaining members. */
  async rotateSenderKey(groupId: string): Promise<SerializedSKDM> {
    return this.runGroupExclusive(groupId, async () => {
      const id = await this.store.getIdentityKeyPair();
      if (!id) throw new Error('No identity key — call initialize() first');
      const cipher = new GroupCipher(this.store, groupId);
      return cipher.rotate(this.userId, id.ed.privateKey, id.ed.publicKey);
    });
  }
}
