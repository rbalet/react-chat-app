/**
 * KDF chains — Double Ratchet spec §5.2.
 *
 * KDF_RK(rk, dh_out): HKDF-SHA256 keyed by dh_out with the root key as
 * salt, 64 bytes out → (new root key, new chain key).
 *
 * KDF_CK(ck): HMAC-SHA256 with ck as key; input 0x01 derives the message
 * key, input 0x02 derives the next chain key (byte-exact spec constants).
 */

import { hkdfSha256, hmacSha256, AEAD_KEY_LENGTH, AEAD_NONCE_LENGTH } from '../core/crypto';
import {
  CHAIN_KEY_SEED,
  KDF_MK_INFO,
  KDF_MK_SALT,
  KDF_RK_INFO,
  MESSAGE_KEY_SEED,
} from '../core/constants';

export interface RootChainStep {
  rootKey: Uint8Array;
  chainKey: Uint8Array;
}

export function kdfRootKey(rootKey: Uint8Array, dhOutput: Uint8Array): RootChainStep {
  const okm = hkdfSha256(dhOutput, rootKey, KDF_RK_INFO, 64);
  return { rootKey: okm.slice(0, 32), chainKey: okm.slice(32, 64) };
}

export interface ChainStep {
  messageKey: Uint8Array;
  nextChainKey: Uint8Array;
}

export function kdfChainKey(chainKey: Uint8Array): ChainStep {
  return {
    messageKey: hmacSha256(chainKey, MESSAGE_KEY_SEED),
    nextChainKey: hmacSha256(chainKey, CHAIN_KEY_SEED),
  };
}

export interface MessageCipherParams {
  key: Uint8Array;
  nonce: Uint8Array;
}

/**
 * Expand a 32-byte message key into AEAD params (spec §5.2 recommends
 * deriving the encryption key and nonce from mk via HKDF). The nonce is
 * deterministic per message key — each mk encrypts exactly one message,
 * and AES-GCM-SIV tolerates misuse anyway.
 */
export function deriveMessageCipherParams(messageKey: Uint8Array): MessageCipherParams {
  const okm = hkdfSha256(messageKey, KDF_MK_SALT, KDF_MK_INFO, AEAD_KEY_LENGTH + AEAD_NONCE_LENGTH);
  return { key: okm.slice(0, AEAD_KEY_LENGTH), nonce: okm.slice(AEAD_KEY_LENGTH) };
}
