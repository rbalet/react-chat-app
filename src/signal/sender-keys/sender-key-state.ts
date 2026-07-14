import { generateSigningKeyPair, randomBytes, sign } from '../core/crypto';
import { MAX_SKIPPED_KEYS_STORED } from '../core/constants';
import { bytesToBase64, base64ToBytes } from '../core/utils';
import { deriveMessageCipherParams, kdfChainKey, type MessageCipherParams } from '../ratchet/chain';
import type { KeyPair } from '../core/types';

/** JSON-safe form stored by the SignalProtocolStore. All bytes base64. */
export interface SerializedSenderKeyState {
  version: 1;
  chainKey: string;
  iteration: number;
  signingPublicKey: string;
  signingPrivateKey: string;
  distributionId: string;
  /** [iteration, base64 message key] pairs — absent means none. */
  skippedKeys?: [number, string][];
}

export class SenderKeyState {
  /**
   * Message keys of iterations that were fast-forwarded past (out-of-order
   * delivery), keyed by iteration. One-shot: consumed on use. Same pattern
   * as the Double Ratchet's skipped message keys (ratchet/ratchet.ts).
   */
  readonly skippedMessageKeys: Map<number, Uint8Array>;

  constructor(
    public chainKey: Uint8Array,
    public iteration: number,
    public signingKey: KeyPair,
    public distributionId: string,
    skippedMessageKeys: Map<number, Uint8Array> = new Map(),
  ) {
    this.skippedMessageKeys = skippedMessageKeys;
  }

  /** Generate a fresh state (called once when the sender first joins a group). */
  static create(): SenderKeyState {
    return new SenderKeyState(
      randomBytes(32),
      0,
      generateSigningKeyPair(),
      crypto.randomUUID(),
    );
  }

  /** Advance the chain by one step. Returns the current iteration + AEAD
   *  params, then increments the internal iteration counter. */
  advance(): { iteration: number; params: MessageCipherParams } {
    const iter = this.iteration;
    const { messageKey, nextChainKey } = kdfChainKey(this.chainKey);
    this.chainKey = nextChainKey;
    this.iteration = iter + 1;
    return { iteration: iter, params: deriveMessageCipherParams(messageKey) };
  }

  /**
   * Fast-forward the chain to `target`, storing every intermediate message
   * key as a skipped key so late messages remain decryptable. Oldest entries
   * are evicted FIFO beyond MAX_SKIPPED_KEYS_STORED to bound memory.
   */
  skipTo(target: number): void {
    while (this.iteration < target) {
      const { messageKey, nextChainKey } = kdfChainKey(this.chainKey);
      this.skippedMessageKeys.set(this.iteration, messageKey);
      this.chainKey = nextChainKey;
      this.iteration += 1;
    }
    while (this.skippedMessageKeys.size > MAX_SKIPPED_KEYS_STORED) {
      const oldest = this.skippedMessageKeys.keys().next().value as number;
      this.skippedMessageKeys.delete(oldest);
    }
  }

  /** Consume the skipped key for `iteration`, if stored (one-shot). */
  takeSkippedKey(iteration: number): MessageCipherParams | undefined {
    const messageKey = this.skippedMessageKeys.get(iteration);
    if (!messageKey) return undefined;
    this.skippedMessageKeys.delete(iteration);
    return deriveMessageCipherParams(messageKey);
  }

  /** Sign a message payload with the chain's signing key. */
  signMessage(payload: Uint8Array): Uint8Array {
    return sign(this.signingKey.privateKey, payload);
  }

  serialize(): SerializedSenderKeyState {
    return {
      version: 1,
      chainKey: bytesToBase64(this.chainKey),
      iteration: this.iteration,
      signingPublicKey: bytesToBase64(this.signingKey.publicKey),
      signingPrivateKey: bytesToBase64(this.signingKey.privateKey),
      distributionId: this.distributionId,
      ...(this.skippedMessageKeys.size > 0 && {
        skippedKeys: [...this.skippedMessageKeys.entries()].map(
          ([iteration, key]): [number, string] => [iteration, bytesToBase64(key)],
        ),
      }),
    };
  }

  static deserialize(s: SerializedSenderKeyState): SenderKeyState {
    if (s.version !== 1) {
      throw new Error(`Unknown SenderKeyState version ${(s as { version: number }).version}`);
    }
    return new SenderKeyState(
      base64ToBytes(s.chainKey),
      s.iteration,
      {
        publicKey: base64ToBytes(s.signingPublicKey),
        privateKey: base64ToBytes(s.signingPrivateKey),
      },
      s.distributionId,
      new Map((s.skippedKeys ?? []).map(([iteration, key]) => [iteration, base64ToBytes(key)])),
    );
  }
}
