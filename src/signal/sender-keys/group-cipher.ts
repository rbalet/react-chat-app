import { aeadDecrypt, aeadEncrypt } from '../core/crypto';
import { base64ToBytes, bytesToBase64, concatBytes, utf8ToBytes } from '../core/utils';
import { SenderKeyState, type SerializedSenderKeyState } from './sender-key-state';
import { createSKDM, verifySKDM, type SerializedSKDM } from './sender-key-distribution';
import type { SignalProtocolStore } from '../store/store-interface';

/** JSON-safe group ciphertext envelope. */
export interface GroupMessage {
  ciphertext: string;
  distributionId: string;
  senderId: string;
}

export class GroupCipher {
  constructor(
    private readonly store: SignalProtocolStore,
    private readonly groupId: string,
  ) {}

  /** Encrypt a group message with the caller's own sender key. The state is
   *  read, advanced, and written back atomically via the store. */
  async encrypt(senderId: string, plaintext: string): Promise<GroupMessage> {
    const raw = await this.store.loadSenderKey(this.groupId, senderId);
    if (!raw) throw new Error('No sender key for this group — call setupSenderKey first');

    const state = SenderKeyState.deserialize(JSON.parse(raw));
    const params = state.advance();

    const ad = utf8ToBytes(this.groupId);
    const encrypted = aeadEncrypt(params.key, params.nonce, utf8ToBytes(plaintext), ad);

    // Write back the advanced state before returning.
    await this.store.storeSenderKey(this.groupId, senderId, JSON.stringify(state.serialize()));

    return {
      ciphertext: bytesToBase64(encrypted),
      distributionId: state.distributionId,
      senderId,
    };
  }

  /** Decrypt a group message from a specific sender. Loads the sender's
   *  state, advances the chain, checks the distributionId matches. */
  async decrypt(message: GroupMessage): Promise<string> {
    const raw = await this.store.loadSenderKey(this.groupId, message.senderId);
    if (!raw) throw new Error(`No sender key for ${message.senderId} in group ${this.groupId}`);

    const state = SenderKeyState.deserialize(JSON.parse(raw));

    // Guard against stale distribution.
    if (state.distributionId !== message.distributionId) {
      throw new Error(
        `Distribution mismatch: message ${message.distributionId} vs stored ${state.distributionId}`,
      );
    }

    // Snapshot the chain key before advancing — if AEAD fails we restore
    // the pre-advance state so the store is never corrupted (same pattern
    // as the Double Ratchet state rollback).
    const snapshot = state.serialize();
    const params = state.advance();
    const ad = utf8ToBytes(this.groupId);
    const ciphertext = base64ToBytes(message.ciphertext);

    try {
      const plaintext = aeadDecrypt(params.key, params.nonce, ciphertext, ad);
      await this.store.storeSenderKey(this.groupId, message.senderId, JSON.stringify(state.serialize()));
      return new TextDecoder().decode(plaintext);
    } catch {
      // Rollback: restore the pre-advance state so the next attempt retries
      // the same message key instead of skipping it.
      await this.store.storeSenderKey(this.groupId, message.senderId, JSON.stringify(snapshot));
      throw new Error('Decryption failed — message may be tampered or from an old sender key');
    }
  }

  /** Create a SKDM for this sender's current key. Callers fan out to each
   *  member via their existing 1:1 sessions. */
  async getDistributionMessage(senderId: string): Promise<SerializedSKDM> {
    const raw = await this.store.loadSenderKey(this.groupId, senderId);
    if (!raw) throw new Error('No sender key — call setupSenderKey first');
    return createSKDM(senderId, SenderKeyState.deserialize(JSON.parse(raw)));
  }

  /** Process a SKDM received from another member. Verifies the signature,
   *  then stores the sender key state so future group messages from that
   *  sender can be decrypted. */
  async processDistributionMessage(senderId: string, skdm: SerializedSKDM): Promise<void> {
    if (!verifySKDM(skdm)) {
      throw new Error('Invalid SKDM signature');
    }

    const state = new SenderKeyState(
      base64ToBytes(skdm.chainKey),
      { publicKey: base64ToBytes(skdm.signingPublicKey), privateKey: new Uint8Array(0) },
      skdm.distributionId,
    );

    // Only the receiving half of the signing key is needed for decryption;
    // the sender keeps the private key to sign new SKDMs on rotation.
    await this.store.storeSenderKey(this.groupId, senderId, JSON.stringify(state.serialize()));
  }

  /** Rotate the sender's key (on member departure). Generate a fresh state,
   *  store it, and return the new SKDM for redistribution. */
  async rotate(senderId: string): Promise<SerializedSKDM> {
    const state = SenderKeyState.create();
    await this.store.storeSenderKey(this.groupId, senderId, JSON.stringify(state.serialize()));
    return createSKDM(senderId, state);
  }
}
