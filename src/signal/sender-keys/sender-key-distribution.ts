import { sign, verify } from '../core/crypto';
import { base64ToBytes, bytesToBase64, concatBytes, u32ToBytes, utf8ToBytes } from '../core/utils';
import type { SenderKeyState } from './sender-key-state';

/** Domain separator so SKDM signatures cannot be replayed in other contexts. */
const SKDM_DOMAIN = utf8ToBytes('Up4itSKDM_v1');

export interface SerializedSKDM {
  senderId: string;
  distributionId: string;
  iteration: number;
  chainKey: string;
  /** The sender's chain Ed25519 signing public key (base64). Used to verify per-message signatures. */
  signingPublicKey: string;
  /** The sender's Ed25519 long-term identity public key (base64). Used for SKDM identity signature verification and TOFU. */
  identityKey: string;
  /** Ed25519 identity signature over (domain || senderId || identityKey || distributionId || iteration || chainKey). */
  signature: string;
}

/**
 * Create a SenderKeyDistributionMessage signed with the sender's long-term
 * identity key. The recipient verifies against the stored remote identity
 * so only the real owner of the identity key can create a valid SKDM.
 */
export function createSKDM(
  senderId: string,
  state: SenderKeyState,
  identityPrivateKey: Uint8Array,
  identityPublicKey: Uint8Array,
): SerializedSKDM {
  const source = concatBytes(
    SKDM_DOMAIN,
    utf8ToBytes(senderId),
    identityPublicKey,
    utf8ToBytes(state.distributionId),
    u32ToBytes(state.iteration),
    state.chainKey,
  );
  return {
    senderId,
    distributionId: state.distributionId,
    iteration: state.iteration,
    chainKey: bytesToBase64(state.chainKey),
    signingPublicKey: bytesToBase64(state.signingKey.publicKey),
    identityKey: bytesToBase64(identityPublicKey),
    signature: bytesToBase64(sign(identityPrivateKey, source)),
  };
}

/**
 * Verify that a SKDM was signed by the claimed identity public key.
 * Returns false if the signature is invalid or the payload is malformed.
 */
export function verifySKDM(skdm: SerializedSKDM, identityPublicKey: Uint8Array): boolean {
  try {
    const chainKey = base64ToBytes(skdm.chainKey);
    const sig = base64ToBytes(skdm.signature);
    const source = concatBytes(
      SKDM_DOMAIN,
      utf8ToBytes(skdm.senderId),
      identityPublicKey,
      utf8ToBytes(skdm.distributionId),
      u32ToBytes(skdm.iteration),
      chainKey,
    );
    return verify(identityPublicKey, source, sig);
  } catch {
    return false;
  }
}
