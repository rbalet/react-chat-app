/**
 * Ratchet message header — Double Ratchet spec §5.1.
 * Fixed wire layout: ratchet public key (32) || PN (u32 BE) || N (u32 BE).
 */

import { bytesToU32, concatBytes, u32ToBytes } from '../core/utils';

export const HEADER_LENGTH = 40;

export interface RatchetHeader {
  /** Sender's current DH ratchet public key. */
  publicKey: Uint8Array;
  /** Length of the previous sending chain (PN). */
  previousChainLength: number;
  /** Message number in the current chain (N). */
  messageNumber: number;
}

export function serializeHeader(header: RatchetHeader): Uint8Array {
  if (header.publicKey.length !== 32) throw new Error('Ratchet key must be 32 bytes');
  return concatBytes(
    header.publicKey,
    u32ToBytes(header.previousChainLength),
    u32ToBytes(header.messageNumber),
  );
}

export function parseHeader(bytes: Uint8Array): RatchetHeader {
  if (bytes.length < HEADER_LENGTH) throw new Error('Truncated ratchet header');
  return {
    publicKey: bytes.slice(0, 32),
    previousChainLength: bytesToU32(bytes, 32),
    messageNumber: bytesToU32(bytes, 36),
  };
}
