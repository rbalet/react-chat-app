import { aeadDecrypt, aeadEncrypt, verify } from '../core/crypto';
import { MAX_GROUP_SKIP } from '../core/constants';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToUtf8,
  concatBytes,
  u32ToBytes,
  utf8ToBytes,
} from '../core/utils';
import { SenderKeyState } from './sender-key-state';
import { SenderKeyRecord } from './sender-key-record';
import { createSKDM, verifySKDM, type SerializedSKDM } from './sender-key-distribution';
import type { MessageCipherParams } from '../ratchet/chain';
import type { SignalProtocolStore } from '../store/store-interface';

/** JSON-safe group ciphertext envelope (matches libsignal's SenderKeyMessage fields). */
export interface GroupMessage {
  ciphertext: string;
  iteration: number;
  distributionId: string;
  senderId: string;
  /** Ed25519 signature by the chain signing key (see groupMessageSignatureSource). */
  signature: string;
}

/**
 * The byte string the chain signing key signs. Variable-length fields carry
 * a u32 length prefix so distinct (ciphertext, distributionId) tuples can
 * never concatenate to the same bytes.
 */
function groupMessageSignatureSource(
  iteration: number,
  ciphertext: Uint8Array,
  distributionId: string,
): Uint8Array {
  const distributionIdBytes = utf8ToBytes(distributionId);
  return concatBytes(
    u32ToBytes(iteration),
    u32ToBytes(ciphertext.length),
    ciphertext,
    u32ToBytes(distributionIdBytes.length),
    distributionIdBytes,
  );
}

export class GroupCipher {
  constructor(
    private readonly store: SignalProtocolStore,
    private readonly groupId: string,
  ) {}

  private async loadRecord(senderId: string): Promise<SenderKeyRecord | undefined> {
    const raw = await this.store.loadSenderKey(this.groupId, senderId);
    return raw === undefined ? undefined : SenderKeyRecord.deserialize(JSON.parse(raw));
  }

  private async persistRecord(senderId: string, record: SenderKeyRecord): Promise<void> {
    await this.store.storeSenderKey(this.groupId, senderId, JSON.stringify(record.serialize()));
  }

  /**
   * Encrypt a group message with the NEWEST chain of the sender's record.
   * The chain key is only persisted after a successful store write — the
   * store itself is not touched before that single write.
   */
  async encrypt(senderId: string, plaintext: string): Promise<GroupMessage> {
    const record = await this.loadRecord(senderId);
    if (!record) throw new Error('No sender key for this group — call setupSenderKey first');

    const state = record.current();
    const { iteration, params } = state.advance();
    const ad = utf8ToBytes(this.groupId);
    const encrypted = aeadEncrypt(params.key, params.nonce, utf8ToBytes(plaintext), ad);

    // Per-message Ed25519 signature by the chain's signing key (libsignal §SenderKeyMessage).
    const sig = state.signMessage(groupMessageSignatureSource(iteration, encrypted, state.distributionId));

    await this.persistRecord(senderId, record);

    return {
      ciphertext: bytesToBase64(encrypted),
      iteration,
      distributionId: state.distributionId,
      senderId,
      signature: bytesToBase64(sig),
    };
  }

  /**
   * Decrypt a group message. The chain is selected by the message's
   * distributionId across ALL live states — so messages still in flight
   * under a pre-rotation chain keep decrypting during the transition.
   * Out-of-order messages use the state's skipped message keys.
   * The store is only written after successful decryption, so a failure
   * leaves the persisted state untouched (implicit rollback).
   */
  async decrypt(message: GroupMessage): Promise<string> {
    const record = await this.loadRecord(message.senderId);
    if (!record) {
      throw new Error(`No sender key for ${message.senderId} in group ${this.groupId}`);
    }

    const state = record.find(message.distributionId);
    if (!state) {
      throw new Error(
        `No sender key state for distribution ${message.distributionId} from ${message.senderId}`,
      );
    }

    // Verify per-message signature BEFORE decrypting (libsignal authenticates each SKM).
    const ciphertext = base64ToBytes(message.ciphertext);
    const sigSource = groupMessageSignatureSource(
      message.iteration,
      ciphertext,
      message.distributionId,
    );
    if (!verify(state.signingKey.publicKey, sigSource, base64ToBytes(message.signature))) {
      throw new Error('Invalid group message signature');
    }

    let params: MessageCipherParams;
    if (message.iteration < state.iteration) {
      // Late arrival: only decryptable if its key was skipped past (one-shot).
      const skipped = state.takeSkippedKey(message.iteration);
      if (!skipped) {
        throw new Error('Group message already processed (no skipped key for this iteration)');
      }
      params = skipped;
    } else {
      if (message.iteration - state.iteration > MAX_GROUP_SKIP) {
        throw new Error('Too many skipped group messages');
      }
      state.skipTo(message.iteration); // no-op when already at the target
      params = state.advance().params;
    }

    const ad = utf8ToBytes(this.groupId);
    let plaintext: Uint8Array;
    try {
      plaintext = aeadDecrypt(params.key, params.nonce, ciphertext, ad);
    } catch {
      // Nothing was persisted since load — stored state is unchanged.
      throw new Error('Decryption failed — message may be tampered or corrupted');
    }
    await this.persistRecord(message.senderId, record);
    return bytesToUtf8(plaintext);
  }

  /** Create a SKDM for the newest chain, signed with the caller's identity key. */
  async getDistributionMessage(
    senderId: string,
    identityPrivateKey: Uint8Array,
    identityPublicKey: Uint8Array,
  ): Promise<SerializedSKDM> {
    const record = await this.loadRecord(senderId);
    if (!record) throw new Error('No sender key — call setupSenderKey first');
    return createSKDM(senderId, record.current(), identityPrivateKey, identityPublicKey);
  }

  /**
   * Process a received SKDM. Verifies the identity-key signature against
   * the caller-provided identity public key, then ADDS the chain to the
   * sender's record (keeping previous chains alive for in-flight messages).
   * Idempotent for an already-known distributionId.
   */
  async processDistributionMessage(
    senderId: string,
    skdm: SerializedSKDM,
    identityPublicKey: Uint8Array,
  ): Promise<void> {
    if (!verifySKDM(skdm, identityPublicKey)) {
      throw new Error('Invalid SKDM signature');
    }
    if (skdm.senderId !== senderId) {
      throw new Error('SKDM senderId does not match transport senderId');
    }

    const record = await this.loadRecord(senderId);
    if (record?.find(skdm.distributionId)) {
      return; // duplicate SKDM for a chain we already track
    }

    const state = new SenderKeyState(
      base64ToBytes(skdm.chainKey),
      skdm.iteration,
      { publicKey: base64ToBytes(skdm.signingPublicKey), privateKey: new Uint8Array(0) },
      skdm.distributionId,
    );

    const updated = record ?? new SenderKeyRecord([]);
    updated.add(state);
    await this.persistRecord(senderId, updated);
  }

  /**
   * Rotate the sender's key (on member departure): ADD a fresh chain —
   * older chains stay decryptable until evicted — and return the new SKDM
   * signed with the identity key.
   */
  async rotate(
    senderId: string,
    identityPrivateKey: Uint8Array,
    identityPublicKey: Uint8Array,
  ): Promise<SerializedSKDM> {
    const record = (await this.loadRecord(senderId)) ?? new SenderKeyRecord([]);
    const state = SenderKeyState.create();
    record.add(state);
    await this.persistRecord(senderId, record);
    return createSKDM(senderId, state, identityPrivateKey, identityPublicKey);
  }
}
