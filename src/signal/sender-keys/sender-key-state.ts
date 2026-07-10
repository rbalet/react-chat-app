import { generateSigningKeyPair, randomBytes } from '../core/crypto';
import { bytesToBase64, base64ToBytes } from '../core/utils';
import { kdfChainKey, type MessageCipherParams } from '../ratchet/chain';
import type { KeyPair } from '../core/types';

/** JSON-safe form stored by the SignalProtocolStore. All bytes base64. */
export interface SerializedSenderKeyState {
  chainKey: string;
  signingPublicKey: string;
  signingPrivateKey: string;
  distributionId: string;
}

export class SenderKeyState {
  constructor(
    public chainKey: Uint8Array,
    public signingKey: KeyPair,
    public distributionId: string,
  ) {}

  /** Generate a fresh state (called once when the sender first joins a group). */
  static create(): SenderKeyState {
    return new SenderKeyState(
      randomBytes(32),
      generateSigningKeyPair(),
      crypto.randomUUID(),
    );
  }

  /** Advance the chain by one step. Returns AEAD-safe key+nonce and mutates
   *  the internal chain key. */
  advance(): MessageCipherParams {
    const { messageKey, nextChainKey } = kdfChainKey(this.chainKey);
    this.chainKey = nextChainKey;
    return mkToParams(messageKey);
  }

  serialize(): SerializedSenderKeyState {
    return {
      chainKey: bytesToBase64(this.chainKey),
      signingPublicKey: bytesToBase64(this.signingKey.publicKey),
      signingPrivateKey: bytesToBase64(this.signingKey.privateKey),
      distributionId: this.distributionId,
    };
  }

  static deserialize(s: SerializedSenderKeyState): SenderKeyState {
    return new SenderKeyState(
      base64ToBytes(s.chainKey),
      {
        publicKey: base64ToBytes(s.signingPublicKey),
        privateKey: base64ToBytes(s.signingPrivateKey),
      },
      s.distributionId,
    );
  }
}

// Re-export the chain's HKDF expansion for message cipher params.
import { deriveMessageCipherParams } from '../ratchet/chain';
function mkToParams(mk: Uint8Array): MessageCipherParams {
  return deriveMessageCipherParams(mk);
}
