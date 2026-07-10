/**
 * Ratchet message wire format and per-message AEAD.
 *
 * SignalMessage layout: version (1) || header (40) || AEAD ciphertext.
 * The AEAD associated data is AD || version || header (Double Ratchet
 * spec §3.4: ENCRYPT(mk, plaintext, CONCAT(AD, header))), so tampering
 * with any header field breaks authentication.
 */

import { aeadDecrypt, aeadEncrypt } from '../core/crypto';
import { WIRE_VERSION } from '../core/constants';
import { concatBytes } from '../core/utils';
import { deriveMessageCipherParams } from './chain';
import { HEADER_LENGTH, parseHeader, serializeHeader, type RatchetHeader } from './header';

export interface ParsedSignalMessage {
  header: RatchetHeader;
  /** version || header — fed back into the AEAD associated data. */
  authenticatedPrefix: Uint8Array;
  ciphertext: Uint8Array;
}

export function encryptRatchetMessage(
  messageKey: Uint8Array,
  header: RatchetHeader,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array {
  const prefix = concatBytes(new Uint8Array([WIRE_VERSION]), serializeHeader(header));
  const { key, nonce } = deriveMessageCipherParams(messageKey);
  const ciphertext = aeadEncrypt(key, nonce, plaintext, concatBytes(associatedData, prefix));
  return concatBytes(prefix, ciphertext);
}

export function parseSignalMessage(message: Uint8Array): ParsedSignalMessage {
  if (message.length < 1 + HEADER_LENGTH) throw new Error('Truncated signal message');
  if (message[0] !== WIRE_VERSION) throw new Error(`Unsupported wire version: ${message[0]}`);
  return {
    header: parseHeader(message.slice(1, 1 + HEADER_LENGTH)),
    authenticatedPrefix: message.slice(0, 1 + HEADER_LENGTH),
    ciphertext: message.slice(1 + HEADER_LENGTH),
  };
}

export function decryptRatchetMessage(
  messageKey: Uint8Array,
  parsed: ParsedSignalMessage,
  associatedData: Uint8Array,
): Uint8Array {
  const { key, nonce } = deriveMessageCipherParams(messageKey);
  return aeadDecrypt(
    key,
    nonce,
    parsed.ciphertext,
    concatBytes(associatedData, parsed.authenticatedPrefix),
  );
}
