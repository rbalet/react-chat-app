/**
 * PreKeyBundle (de)serialization — the JSON-safe form exchanged with the
 * key server (X3DH §3.2). All byte fields are base64.
 */

import { base64ToBytes, bytesToBase64 } from '../core/utils';
import type { PreKeyBundle } from '../core/types';

export interface SerializedPreKeyBundle {
  registrationId: number;
  identityKey: string;
  signedPreKey: {
    id: number;
    publicKey: string;
    signature: string;
  };
  oneTimePreKey?: {
    id: number;
    publicKey: string;
  };
}

export function serializePreKeyBundle(bundle: PreKeyBundle): SerializedPreKeyBundle {
  return {
    registrationId: bundle.registrationId,
    identityKey: bytesToBase64(bundle.identityKey),
    signedPreKey: {
      id: bundle.signedPreKey.id,
      publicKey: bytesToBase64(bundle.signedPreKey.publicKey),
      signature: bytesToBase64(bundle.signedPreKey.signature),
    },
    ...(bundle.oneTimePreKey && {
      oneTimePreKey: {
        id: bundle.oneTimePreKey.id,
        publicKey: bytesToBase64(bundle.oneTimePreKey.publicKey),
      },
    }),
  };
}

export function deserializePreKeyBundle(bundle: SerializedPreKeyBundle): PreKeyBundle {
  return {
    registrationId: bundle.registrationId,
    identityKey: base64ToBytes(bundle.identityKey),
    signedPreKey: {
      id: bundle.signedPreKey.id,
      publicKey: base64ToBytes(bundle.signedPreKey.publicKey),
      signature: base64ToBytes(bundle.signedPreKey.signature),
    },
    ...(bundle.oneTimePreKey && {
      oneTimePreKey: {
        id: bundle.oneTimePreKey.id,
        publicKey: base64ToBytes(bundle.oneTimePreKey.publicKey),
      },
    }),
  };
}
