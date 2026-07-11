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
 * The byte string the identity key signs. Variable-length fields carry a
 * u32 length prefix so no two distinct field tuples can concatenate to the
 * same bytes (no ambiguity between e.g. senderId and distributionId).
 */
function skdmSignatureSource(
  senderId: string,
  identityPublicKey: Uint8Array,
  distributionId: string,
  iteration: number,
  chainKey: Uint8Array,
): Uint8Array {
  const senderIdBytes = utf8ToBytes(senderId);
  const distributionIdBytes = utf8ToBytes(distributionId);
  return concatBytes(
    SKDM_DOMAIN,
    u32ToBytes(senderIdBytes.length),
    senderIdBytes,
    identityPublicKey,
    u32ToBytes(distributionIdBytes.length),
    distributionIdBytes,
    u32ToBytes(iteration),
    chainKey,
  );
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
  const source = skdmSignatureSource(
    senderId,
    identityPublicKey,
    state.distributionId,
    state.iteration,
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
    const source = skdmSignatureSource(
      skdm.senderId,
      identityPublicKey,
      skdm.distributionId,
      skdm.iteration,
      base64ToBytes(skdm.chainKey),
    );
    return verify(identityPublicKey, source, base64ToBytes(skdm.signature));
  } catch {
    return false;
  }
}
