import { sign, verify } from '../core/crypto';
import { base64ToBytes, bytesToBase64, concatBytes, utf8ToBytes } from '../core/utils';
import type { SenderKeyState } from './sender-key-state';

export interface SerializedSKDM {
  senderId: string;
  distributionId: string;
  chainKey: string;
  signingPublicKey: string;
  signature: string;
}

/**
 * Create a SenderKeyDistributionMessage — the "seed" another member needs
 * to start decrypting this sender's group messages. Signed with the
 * sender's own signing key so recipients can verify the author.
 */
export function createSKDM(senderId: string, state: SenderKeyState): SerializedSKDM {
  const source = concatBytes(
    utf8ToBytes(state.distributionId),
    state.chainKey,
  );
  return {
    senderId,
    distributionId: state.distributionId,
    chainKey: bytesToBase64(state.chainKey),
    signingPublicKey: bytesToBase64(state.signingKey.publicKey),
    signature: bytesToBase64(sign(state.signingKey.privateKey, source)),
  };
}

/**
 * Verify a SKDM signature. Returns false if the signature is invalid or
 * the payload is malformed — recipients MUST reject unverified SKDMs.
 */
export function verifySKDM(skdm: SerializedSKDM): boolean {
  try {
    const chainKey = base64ToBytes(skdm.chainKey);
    const signingPublicKey = base64ToBytes(skdm.signingPublicKey);
    const sig = base64ToBytes(skdm.signature);
    const source = concatBytes(utf8ToBytes(skdm.distributionId), chainKey);
    return verify(signingPublicKey, source, sig);
  } catch {
    return false;
  }
}
