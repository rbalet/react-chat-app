/**
 * Double Ratchet state machine — Double Ratchet spec §3.5, with skipped
 * message keys per §2.6/§3.5 (header-key-free variant).
 *
 * Forward secrecy: every message key comes from a one-way HMAC chain and
 * is deleted after use. Post-compromise security: each round-trip runs a
 * DH ratchet step that mixes fresh DH output into the root key.
 */

import { dh, generateDHKeyPair } from '../core/crypto';
import { MAX_SKIP, MAX_SKIPPED_KEYS_STORED } from '../core/constants';
import { base64ToBytes, bytesToBase64, equalBytes } from '../core/utils';
import { kdfChainKey, kdfRootKey } from './chain';
import { decryptRatchetMessage, encryptRatchetMessage, parseSignalMessage } from './message';
import type { KeyPair } from '../core/types';

interface RatchetState {
  rootKey: Uint8Array;
  /** Our current DH ratchet pair (DHs). */
  sendingRatchetKey: KeyPair;
  /** Their current DH ratchet public key (DHr) — null on Bob before first receive. */
  receivingRatchetKey: Uint8Array | null;
  sendingChainKey: Uint8Array | null;
  receivingChainKey: Uint8Array | null;
  sendMessageNumber: number;
  receiveMessageNumber: number;
  previousSendingChainLength: number;
  /** mk indexed by `${base64(ratchetPub)}:${messageNumber}` (insertion-ordered). */
  skippedMessageKeys: Map<string, Uint8Array>;
}

function skippedKeyId(ratchetPublicKey: Uint8Array, messageNumber: number): string {
  return `${bytesToBase64(ratchetPublicKey)}:${messageNumber}`;
}

export class DoubleRatchet {
  private state: RatchetState;
  /** X3DH associated data, bound to every message's AEAD. */
  private readonly associatedData: Uint8Array;

  private constructor(state: RatchetState, associatedData: Uint8Array) {
    this.state = state;
    this.associatedData = associatedData;
  }

  /**
   * Initiator init (spec §3.5 RatchetInitAlice): Bob's signed prekey acts
   * as his initial ratchet key, so Alice can ratchet immediately and send
   * without waiting for a reply.
   */
  static initAlice(
    sharedKey: Uint8Array,
    theirRatchetKey: Uint8Array,
    associatedData: Uint8Array,
  ): DoubleRatchet {
    const sendingRatchetKey = generateDHKeyPair();
    const { rootKey, chainKey } = kdfRootKey(
      sharedKey,
      dh(sendingRatchetKey.privateKey, theirRatchetKey),
    );
    return new DoubleRatchet(
      {
        rootKey,
        sendingRatchetKey,
        receivingRatchetKey: theirRatchetKey,
        sendingChainKey: chainKey,
        receivingChainKey: null,
        sendMessageNumber: 0,
        receiveMessageNumber: 0,
        previousSendingChainLength: 0,
        skippedMessageKeys: new Map(),
      },
      associatedData,
    );
  }

  /** Responder init (spec §3.5 RatchetInitBob): our SPK pair is the initial ratchet key. */
  static initBob(
    sharedKey: Uint8Array,
    ourRatchetKey: KeyPair,
    associatedData: Uint8Array,
  ): DoubleRatchet {
    return new DoubleRatchet(
      {
        rootKey: sharedKey,
        sendingRatchetKey: ourRatchetKey,
        receivingRatchetKey: null,
        sendingChainKey: null,
        receivingChainKey: null,
        sendMessageNumber: 0,
        receiveMessageNumber: 0,
        previousSendingChainLength: 0,
        skippedMessageKeys: new Map(),
      },
      associatedData,
    );
  }

  /** Spec §3.5 RatchetEncrypt. Returns the serialized SignalMessage. */
  encrypt(plaintext: Uint8Array): Uint8Array {
    const s = this.state;
    if (!s.sendingChainKey) {
      // Only ever reachable for a responder that tries to send before having
      // received the initiator's first message — a session-layer bug.
      throw new Error('Double Ratchet: no sending chain established yet');
    }
    const { messageKey, nextChainKey } = kdfChainKey(s.sendingChainKey);
    const message = encryptRatchetMessage(
      messageKey,
      {
        publicKey: s.sendingRatchetKey.publicKey,
        previousChainLength: s.previousSendingChainLength,
        messageNumber: s.sendMessageNumber,
      },
      plaintext,
      this.associatedData,
    );
    s.sendingChainKey = nextChainKey;
    s.sendMessageNumber += 1;
    return message;
  }

  /**
   * Spec §3.5 RatchetDecrypt. State is committed only if decryption
   * authenticates — a forged or corrupt message leaves the ratchet intact.
   */
  decrypt(message: Uint8Array): Uint8Array {
    const snapshot = this.snapshotState();
    try {
      return this.decryptInternal(message);
    } catch (error) {
      this.state = snapshot;
      throw error;
    }
  }

  private decryptInternal(message: Uint8Array): Uint8Array {
    const parsed = parseSignalMessage(message);
    const { header } = parsed;
    const s = this.state;

    // §3.5 TrySkippedMessageKeys: a previously-skipped (out-of-order) message.
    const skippedId = skippedKeyId(header.publicKey, header.messageNumber);
    const skippedKey = s.skippedMessageKeys.get(skippedId);
    if (skippedKey) {
      const plaintext = decryptRatchetMessage(skippedKey, parsed, this.associatedData);
      s.skippedMessageKeys.delete(skippedId); // one-shot: forward secrecy
      return plaintext;
    }

    // New remote ratchet key → close out the previous receiving chain, then DH-ratchet.
    if (!s.receivingRatchetKey || !equalBytes(header.publicKey, s.receivingRatchetKey)) {
      this.skipReceivingMessageKeys(header.previousChainLength);
      this.dhRatchetStep(header.publicKey);
    }

    this.skipReceivingMessageKeys(header.messageNumber);

    if (!s.receivingChainKey) throw new Error('Double Ratchet: no receiving chain');
    const { messageKey, nextChainKey } = kdfChainKey(s.receivingChainKey);
    const plaintext = decryptRatchetMessage(messageKey, parsed, this.associatedData);
    s.receivingChainKey = nextChainKey;
    s.receiveMessageNumber += 1;
    return plaintext;
  }

  /** Spec §3.5 SkipMessageKeys: derive and store mk for gaps up to `until`. */
  private skipReceivingMessageKeys(until: number): void {
    const s = this.state;
    if (s.receiveMessageNumber + MAX_SKIP < until) {
      throw new Error(`Double Ratchet: too many skipped messages (${until - s.receiveMessageNumber})`);
    }
    if (!s.receivingChainKey || !s.receivingRatchetKey) return;
    while (s.receiveMessageNumber < until) {
      const { messageKey, nextChainKey } = kdfChainKey(s.receivingChainKey);
      s.skippedMessageKeys.set(
        skippedKeyId(s.receivingRatchetKey, s.receiveMessageNumber),
        messageKey,
      );
      s.receivingChainKey = nextChainKey;
      s.receiveMessageNumber += 1;
    }
    // Bound memory: evict oldest entries beyond the global cap (spec §6).
    while (s.skippedMessageKeys.size > MAX_SKIPPED_KEYS_STORED) {
      const oldest = s.skippedMessageKeys.keys().next().value as string;
      s.skippedMessageKeys.delete(oldest);
    }
  }

  /** Spec §3.5 DHRatchet: two KDF_RK steps around a fresh ratchet key pair. */
  private dhRatchetStep(theirRatchetKey: Uint8Array): void {
    const s = this.state;
    s.previousSendingChainLength = s.sendMessageNumber;
    s.sendMessageNumber = 0;
    s.receiveMessageNumber = 0;
    s.receivingRatchetKey = theirRatchetKey;

    const receiving = kdfRootKey(s.rootKey, dh(s.sendingRatchetKey.privateKey, theirRatchetKey));
    s.receivingChainKey = receiving.chainKey;

    s.sendingRatchetKey = generateDHKeyPair();
    const sending = kdfRootKey(receiving.rootKey, dh(s.sendingRatchetKey.privateKey, theirRatchetKey));
    s.rootKey = sending.rootKey;
    s.sendingChainKey = sending.chainKey;
  }

  private snapshotState(): RatchetState {
    // Uint8Array fields are never mutated in place (always reassigned),
    // so copying references is safe; the map is copied shallowly.
    return { ...this.state, skippedMessageKeys: new Map(this.state.skippedMessageKeys) };
  }

  serialize(): SerializedRatchet {
    const s = this.state;
    return {
      rootKey: bytesToBase64(s.rootKey),
      sendingRatchetKey: {
        publicKey: bytesToBase64(s.sendingRatchetKey.publicKey),
        privateKey: bytesToBase64(s.sendingRatchetKey.privateKey),
      },
      receivingRatchetKey: s.receivingRatchetKey ? bytesToBase64(s.receivingRatchetKey) : null,
      sendingChainKey: s.sendingChainKey ? bytesToBase64(s.sendingChainKey) : null,
      receivingChainKey: s.receivingChainKey ? bytesToBase64(s.receivingChainKey) : null,
      sendMessageNumber: s.sendMessageNumber,
      receiveMessageNumber: s.receiveMessageNumber,
      previousSendingChainLength: s.previousSendingChainLength,
      skippedMessageKeys: [...s.skippedMessageKeys.entries()].map(([id, key]) => [
        id,
        bytesToBase64(key),
      ]),
      associatedData: bytesToBase64(this.associatedData),
    };
  }

  static deserialize(data: SerializedRatchet): DoubleRatchet {
    return new DoubleRatchet(
      {
        rootKey: base64ToBytes(data.rootKey),
        sendingRatchetKey: {
          publicKey: base64ToBytes(data.sendingRatchetKey.publicKey),
          privateKey: base64ToBytes(data.sendingRatchetKey.privateKey),
        },
        receivingRatchetKey: data.receivingRatchetKey
          ? base64ToBytes(data.receivingRatchetKey)
          : null,
        sendingChainKey: data.sendingChainKey ? base64ToBytes(data.sendingChainKey) : null,
        receivingChainKey: data.receivingChainKey ? base64ToBytes(data.receivingChainKey) : null,
        sendMessageNumber: data.sendMessageNumber,
        receiveMessageNumber: data.receiveMessageNumber,
        previousSendingChainLength: data.previousSendingChainLength,
        skippedMessageKeys: new Map(
          data.skippedMessageKeys.map(([id, key]) => [id, base64ToBytes(key)]),
        ),
      },
      base64ToBytes(data.associatedData),
    );
  }
}

export interface SerializedRatchet {
  rootKey: string;
  sendingRatchetKey: { publicKey: string; privateKey: string };
  receivingRatchetKey: string | null;
  sendingChainKey: string | null;
  receivingChainKey: string | null;
  sendMessageNumber: number;
  receiveMessageNumber: number;
  previousSendingChainLength: number;
  skippedMessageKeys: [string, string][];
  associatedData: string;
}
