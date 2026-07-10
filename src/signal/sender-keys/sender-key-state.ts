import { generateSigningKeyPair, randomBytes, sign } from '../core/crypto';
import { bytesToBase64, base64ToBytes } from '../core/utils';
import { kdfChainKey, type MessageCipherParams } from '../ratchet/chain';
import type { KeyPair } from '../core/types';

/** JSON-safe form stored by the SignalProtocolStore. All bytes base64. */
export interface SerializedSenderKeyState {
  version: 1;
  chainKey: string;
  iteration: number;
  signingPublicKey: string;
  signingPrivateKey: string;
  distributionId: string;
}

export class SenderKeyState {
  constructor(
    public chainKey: Uint8Array,
    public iteration: number,
    public signingKey: KeyPair,
    public distributionId: string,
  ) {}

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
    return { iteration: iter, params: mkToParams(messageKey) };
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
    };
  }

  static deserialize(s: SerializedSenderKeyState): SenderKeyState {
    if (s.version !== 1) throw new Error(`Unknown SenderKeyState version ${(s as any).version}`);
    return new SenderKeyState(
      base64ToBytes(s.chainKey),
      s.iteration,
      {
        publicKey: base64ToBytes(s.signingPublicKey),
        privateKey: base64ToBytes(s.signingPrivateKey),
      },
      s.distributionId,
    );
  }
}

import { deriveMessageCipherParams } from '../ratchet/chain';
function mkToParams(mk: Uint8Array): MessageCipherParams {
  return deriveMessageCipherParams(mk);
}
