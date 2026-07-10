import { aeadDecrypt, aeadEncrypt, verify } from '../core/crypto';
import { base64ToBytes, bytesToBase64, concatBytes, u32ToBytes, utf8ToBytes } from '../core/utils';
import { SenderKeyState } from './sender-key-state';
import { createSKDM, verifySKDM, type SerializedSKDM } from './sender-key-distribution';
import type { SignalProtocolStore } from '../store/store-interface';

/** JSON-safe group ciphertext envelope (matches libsignal's SenderKeyMessage fields). */
export interface GroupMessage {
  ciphertext: string;
  iteration: number;
  distributionId: string;
  senderId: string;
  /** Ed25519 signature over (iteration || ciphertext || distributionId) by the chain signing key. */
  signature: string;
}

export class GroupCipher {
  constructor(
    private readonly store: SignalProtocolStore,
    private readonly groupId: string,
  ) {}

  /**
   * Encrypt a group message. The chain key is advanced; on store write
   * failure the pre-advance snapshot is restored so the chain is never lost.
   */
  async encrypt(senderId: string, plaintext: string): Promise<GroupMessage> {
    const raw = await this.store.loadSenderKey(this.groupId, senderId);
    if (!raw) throw new Error('No sender key for this group — call setupSenderKey first');

    const state = SenderKeyState.deserialize(JSON.parse(raw));
    const snapshot = state.serialize();

    const { iteration, params } = state.advance();
    const ad = utf8ToBytes(this.groupId);
    const encrypted = aeadEncrypt(params.key, params.nonce, utf8ToBytes(plaintext), ad);

    // Per-message Ed25519 signature by the chain's signing key (libsignal §SenderKeyMessage).
    const sigSource = concatBytes(u32ToBytes(iteration), encrypted, utf8ToBytes(state.distributionId));
    const sig = state.signMessage(sigSource);

    try {
      await this.store.storeSenderKey(this.groupId, senderId, JSON.stringify(state.serialize()));
    } catch {
      await this.store.storeSenderKey(this.groupId, senderId, JSON.stringify(snapshot));
      throw new Error('Failed to persist sender key state after encrypt');
    }

    return {
      ciphertext: bytesToBase64(encrypted),
      iteration,
      distributionId: state.distributionId,
      senderId,
      signature: bytesToBase64(sig),
    };
  }

  /** Decrypt a group message with snapshot/rollback on AEAD failure.
   *  Verifies the chain signing key signature before decrypting. */
  async decrypt(message: GroupMessage): Promise<string> {
    const raw = await this.store.loadSenderKey(this.groupId, message.senderId);
    if (!raw) throw new Error(`No sender key for ${message.senderId} in group ${this.groupId}`);

    const state = SenderKeyState.deserialize(JSON.parse(raw));

    if (state.distributionId !== message.distributionId) {
      throw new Error(
        `Distribution mismatch: message ${message.distributionId} vs stored ${state.distributionId}`,
      );
    }

    // Verify per-message signature BEFORE decrypting (libsignal authenticates each SKM).
    const ciphertext = base64ToBytes(message.ciphertext);
    const sig = base64ToBytes(message.signature);
    const sigSource = concatBytes(u32ToBytes(message.iteration), ciphertext, utf8ToBytes(message.distributionId));
    if (!verify(state.signingKey.publicKey, sigSource, sig)) {
      throw new Error('Invalid group message signature');
    }

    // Out-of-order handling: if the message iteration is ahead, fast-forward
    // the chain and derive the correct message key.
    let params;
    const snapshot = state.serialize();
    if (message.iteration > state.iteration) {
      const jumps = message.iteration - state.iteration;
      if (jumps > 25000) throw new Error('Too many skipped group messages');
      // Advance to the target iteration, discarding intermediate message keys
      // (sender keys don't buffer skipped keys — implementations vary).
      while (state.iteration < message.iteration) {
        state.advance();
      }
      // One more advance to get the current message key
      const result = state.advance();
      params = result.params;
    } else if (message.iteration === state.iteration) {
      const result = state.advance();
      params = result.params;
    } else {
      // message.iteration < state.iteration: duplicate or already processed
      throw new Error('Duplicate or out-of-order group message already processed');
    }

    const ad = utf8ToBytes(this.groupId);

    try {
      const plaintext = aeadDecrypt(params.key, params.nonce, ciphertext, ad);
      await this.store.storeSenderKey(this.groupId, message.senderId, JSON.stringify(state.serialize()));
      return new TextDecoder().decode(plaintext);
    } catch {
      await this.store.storeSenderKey(this.groupId, message.senderId, JSON.stringify(snapshot));
      throw new Error('Decryption failed — message may be tampered or from an old sender key');
    }
  }

  /** Create a SKDM signed with the caller's identity key. */
  async getDistributionMessage(
    senderId: string,
    identityPrivateKey: Uint8Array,
    identityPublicKey: Uint8Array,
  ): Promise<SerializedSKDM> {
    const raw = await this.store.loadSenderKey(this.groupId, senderId);
    if (!raw) throw new Error('No sender key — call setupSenderKey first');
    return createSKDM(senderId, SenderKeyState.deserialize(JSON.parse(raw)), identityPrivateKey, identityPublicKey);
  }

  /**
   * Process a received SKDM. Verifies the identity-key signature against
   * the caller-provided identity public key, then stores the sender key
   * state. Rejects replays (an existing state with a different distributionId).
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

    const existing = await this.store.loadSenderKey(this.groupId, senderId);
    if (existing) {
      const prev = SenderKeyState.deserialize(JSON.parse(existing));
      if (prev.distributionId === skdm.distributionId) {
        return;
      }
    }

    const state = new SenderKeyState(
      base64ToBytes(skdm.chainKey),
      skdm.iteration,
      { publicKey: base64ToBytes(skdm.signingPublicKey), privateKey: new Uint8Array(0) },
      skdm.distributionId,
    );

    await this.store.storeSenderKey(this.groupId, senderId, JSON.stringify(state.serialize()));
  }

  /** Rotate the sender's key (on member departure). Generates a fresh state
   *  and returns the new SKDM signed with the identity key. */
  async rotate(
    senderId: string,
    identityPrivateKey: Uint8Array,
    identityPublicKey: Uint8Array,
  ): Promise<SerializedSKDM> {
    const state = SenderKeyState.create();
    await this.store.storeSenderKey(this.groupId, senderId, JSON.stringify(state.serialize()));
    return createSKDM(senderId, state, identityPrivateKey, identityPublicKey);
  }
}
