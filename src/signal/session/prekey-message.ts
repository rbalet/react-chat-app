/**
 * PreKey message envelope — the first message(s) of a session, carrying
 * the X3DH handshake data alongside a regular ratchet message (X3DH §3.3
 * "the initial message"). Sent until the initiator receives a reply.
 *
 * Wire layout:
 *   version (1) || flags (1, bit0 = has one-time prekey)
 *   || registrationId (u32) || signedPreKeyId (u32) || [preKeyId (u32)]
 *   || identityKey (Ed25519, 32) || baseKey (X25519 EK_A, 32)
 *   || embedded SignalMessage (rest)
 */

import { WIRE_VERSION } from '../core/constants';
import { bytesToU32, concatBytes, u32ToBytes } from '../core/utils';

export interface PreKeyMessage {
  registrationId: number;
  signedPreKeyId: number;
  preKeyId?: number;
  /** Sender's Ed25519 public identity key. */
  identityKey: Uint8Array;
  /** Sender's X3DH ephemeral public key (EK_A). */
  baseKey: Uint8Array;
  /** The embedded serialized SignalMessage. */
  message: Uint8Array;
}

const FLAG_HAS_ONE_TIME_PREKEY = 0x01;

export function serializePreKeyMessage(msg: PreKeyMessage): Uint8Array {
  if (msg.identityKey.length !== 32 || msg.baseKey.length !== 32) {
    throw new Error('PreKey message keys must be 32 bytes');
  }
  const hasOpk = msg.preKeyId !== undefined;
  return concatBytes(
    new Uint8Array([WIRE_VERSION, hasOpk ? FLAG_HAS_ONE_TIME_PREKEY : 0]),
    u32ToBytes(msg.registrationId),
    u32ToBytes(msg.signedPreKeyId),
    ...(hasOpk ? [u32ToBytes(msg.preKeyId!)] : []),
    msg.identityKey,
    msg.baseKey,
    msg.message,
  );
}

export function parsePreKeyMessage(bytes: Uint8Array): PreKeyMessage {
  if (bytes.length < 2) throw new Error('Truncated prekey message');
  if (bytes[0] !== WIRE_VERSION) throw new Error(`Unsupported wire version: ${bytes[0]}`);
  const hasOpk = ((bytes[1]! & FLAG_HAS_ONE_TIME_PREKEY) as number) !== 0;
  const fixedLength = 2 + 4 + 4 + (hasOpk ? 4 : 0) + 32 + 32;
  if (bytes.length <= fixedLength) throw new Error('Truncated prekey message');

  let offset = 2;
  const registrationId = bytesToU32(bytes, offset);
  offset += 4;
  const signedPreKeyId = bytesToU32(bytes, offset);
  offset += 4;
  let preKeyId: number | undefined;
  if (hasOpk) {
    preKeyId = bytesToU32(bytes, offset);
    offset += 4;
  }
  const identityKey = bytes.slice(offset, offset + 32);
  offset += 32;
  const baseKey = bytes.slice(offset, offset + 32);
  offset += 32;
  const message = bytes.slice(offset);

  return {
    registrationId,
    signedPreKeyId,
    ...(preKeyId !== undefined && { preKeyId }),
    identityKey,
    baseKey,
    message,
  };
}
