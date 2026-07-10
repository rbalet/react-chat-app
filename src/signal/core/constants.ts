/**
 * Protocol constants — see BRIEF.md §13.
 *
 * The HKDF info strings are application-chosen (X3DH spec §2.1 leaves them
 * to the implementer). They are deliberately distinct from Signal's own,
 * so this protocol is standalone, NOT wire-compatible with Signal clients.
 */

import { utf8ToBytes } from './utils';

/** X3DH domain separator F: 32 bytes of 0xFF for curve X25519 (X3DH §2.2). */
export const X3DH_F = new Uint8Array(32).fill(0xff);
export const X3DH_INFO = utf8ToBytes('Up4itX3DH_v1');
/** Zero-filled salt, one hash output length (X3DH §2.2). */
export const X3DH_SALT = new Uint8Array(32);

/** Double Ratchet KDF_RK info (Double Ratchet spec §5.2). */
export const KDF_RK_INFO = utf8ToBytes('Up4itRatchet_v1');
/** Message-key expansion info (Double Ratchet spec §5.2). */
export const KDF_MK_INFO = utf8ToBytes('Up4itMessageKeys_v1');
export const KDF_MK_SALT = new Uint8Array(32);

/** KDF_CK constants — byte-exact from the Double Ratchet spec §5.2. */
export const MESSAGE_KEY_SEED = new Uint8Array([0x01]);
export const CHAIN_KEY_SEED = new Uint8Array([0x02]);

/** Max skipped message keys per chain advance (Double Ratchet spec §6). */
export const MAX_SKIP = 1000;
/** Global cap on stored skipped keys (FIFO eviction) to bound memory. */
export const MAX_SKIPPED_KEYS_STORED = 2000;

/** Wire format version of our message serialization. */
export const WIRE_VERSION = 1;

/** Public key wire encoding type bytes (Encode(PK), X3DH §2.5). */
export const KEY_TYPE_X25519 = 0x05;
export const KEY_TYPE_ED25519 = 0x06;

export const DEFAULT_PREKEY_BATCH_SIZE = 100;
export const SIGNED_PREKEY_ROTATION_DAYS = 7;

/** Registration ids are 14-bit like libsignal's convention: [1, 16380]. */
export const MAX_REGISTRATION_ID = 16380;
