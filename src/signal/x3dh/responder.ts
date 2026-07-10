/**
 * X3DH responder (Bob) — X3DH spec §3.4.
 *
 * Bob receives Alice's identity key and ephemeral key in her first message
 * and recomputes the same DH values with the private halves of his own
 * signed prekey / one-time prekey:
 *
 *   DH1 = DH(SPK_B, IK_A)
 *   DH2 = DH(IK_B, EK_A)
 *   DH3 = DH(SPK_B, EK_A)
 *   DH4 = DH(OPK_B, EK_A)          (if Alice used a one-time prekey)
 */

import { dh, encodePublicKey, hkdfSha256 } from '../core/crypto';
import { X3DH_F, X3DH_INFO, X3DH_SALT } from '../core/constants';
import { concatBytes } from '../core/utils';
import { identityDHPublicKey } from '../identity/identity-key';
import type { IdentityKeyPair, KeyPair } from '../core/types';

export interface X3DHResponderResult {
  sharedKey: Uint8Array;
  /** AD = Encode(IK_A) || Encode(IK_B) — same ordering as the initiator. */
  associatedData: Uint8Array;
}

export function x3dhRespond(
  ourIdentity: IdentityKeyPair,
  ourSignedPreKey: KeyPair,
  ourOneTimePreKey: KeyPair | undefined,
  theirIdentityKeyEd: Uint8Array,
  theirEphemeralKey: Uint8Array,
): X3DHResponderResult {
  const theirIdentityDH = identityDHPublicKey(theirIdentityKeyEd);

  const dh1 = dh(ourSignedPreKey.privateKey, theirIdentityDH);
  const dh2 = dh(ourIdentity.x.privateKey, theirEphemeralKey);
  const dh3 = dh(ourSignedPreKey.privateKey, theirEphemeralKey);
  const dhParts = [X3DH_F, dh1, dh2, dh3];
  if (ourOneTimePreKey) {
    dhParts.push(dh(ourOneTimePreKey.privateKey, theirEphemeralKey));
  }

  const sharedKey = hkdfSha256(concatBytes(...dhParts), X3DH_SALT, X3DH_INFO, 32);

  const associatedData = concatBytes(
    encodePublicKey(theirIdentityKeyEd, 'ed25519'),
    encodePublicKey(ourIdentity.ed.publicKey, 'ed25519'),
  );

  return { sharedKey, associatedData };
}
