/**
 * X3DH initiator (Alice) — X3DH spec §3.3.
 *
 * Given Bob's prekey bundle, verify the signed prekey, generate an
 * ephemeral key EK_A and compute:
 *
 *   DH1 = DH(IK_A, SPK_B)
 *   DH2 = DH(EK_A, IK_B)
 *   DH3 = DH(EK_A, SPK_B)
 *   DH4 = DH(EK_A, OPK_B)          (if a one-time prekey is present)
 *   SK  = KDF(F || DH1 || DH2 || DH3 [|| DH4])
 *
 * where F is 32 bytes of 0xFF (domain separation, §2.2) and KDF is
 * HKDF-SHA256 with a zero-filled salt and our application info string.
 */

import {
  dh,
  encodePublicKey,
  generateDHKeyPair,
  hkdfSha256,
  verify,
} from '../core/crypto';
import { X3DH_F, X3DH_INFO, X3DH_SALT } from '../core/constants';
import { concatBytes } from '../core/utils';
import { identityDHPublicKey } from '../identity/identity-key';
import type { IdentityKeyPair, KeyPair, PreKeyBundle } from '../core/types';

export interface X3DHInitiatorResult {
  /** The 32-byte session secret SK. */
  sharedKey: Uint8Array;
  /** Alice's ephemeral pair; the public half goes into the first message. */
  ephemeralKey: KeyPair;
  /** AD = Encode(IK_A) || Encode(IK_B), bound to every ratchet message (§3.3). */
  associatedData: Uint8Array;
}

export function x3dhInitiate(
  ourIdentity: IdentityKeyPair,
  theirBundle: PreKeyBundle,
): X3DHInitiatorResult {
  const spkPublic = theirBundle.signedPreKey.publicKey;

  // §3.3: Alice MUST verify the SPK signature before using the bundle.
  const spkSignatureValid = verify(
    theirBundle.identityKey,
    encodePublicKey(spkPublic, 'x25519'),
    theirBundle.signedPreKey.signature,
  );
  if (!spkSignatureValid) {
    throw new Error('X3DH: invalid signed prekey signature');
  }

  const theirIdentityDH = identityDHPublicKey(theirBundle.identityKey);
  const ephemeralKey = generateDHKeyPair();

  const dh1 = dh(ourIdentity.x.privateKey, spkPublic);
  const dh2 = dh(ephemeralKey.privateKey, theirIdentityDH);
  const dh3 = dh(ephemeralKey.privateKey, spkPublic);
  const dhParts = [X3DH_F, dh1, dh2, dh3];
  if (theirBundle.oneTimePreKey) {
    dhParts.push(dh(ephemeralKey.privateKey, theirBundle.oneTimePreKey.publicKey));
  }

  const sharedKey = hkdfSha256(concatBytes(...dhParts), X3DH_SALT, X3DH_INFO, 32);

  const associatedData = concatBytes(
    encodePublicKey(ourIdentity.ed.publicKey, 'ed25519'),
    encodePublicKey(theirBundle.identityKey, 'ed25519'),
  );

  return { sharedKey, ephemeralKey, associatedData };
}
