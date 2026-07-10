/**
 * Session record: the Double Ratchet state plus session metadata,
 * serialized as an opaque JSON string for the store.
 */

import { DoubleRatchet, type SerializedRatchet } from '../ratchet/ratchet';
import { base64ToBytes, bytesToBase64 } from '../core/utils';

/** Handshake data the initiator re-sends until the first reply arrives. */
export interface PendingPreKey {
  registrationId: number;
  signedPreKeyId: number;
  preKeyId?: number;
  /** Our X3DH ephemeral public key (EK_A), base64. */
  baseKey: string;
}

interface SessionRecordData {
  version: 1;
  ratchet: SerializedRatchet;
  /** Peer's Ed25519 public identity key, base64. */
  theirIdentityKey: string;
  /** Initiator only — cleared on first successful inbound decrypt. */
  pendingPreKey?: PendingPreKey;
  /** Responder only — makes duplicate prekey messages idempotent. */
  theirBaseKey?: string;
}

export class SessionRecord {
  ratchet: DoubleRatchet;
  theirIdentityKey: Uint8Array;
  pendingPreKey?: PendingPreKey;
  theirBaseKey?: Uint8Array;

  constructor(
    ratchet: DoubleRatchet,
    theirIdentityKey: Uint8Array,
    options: { pendingPreKey?: PendingPreKey; theirBaseKey?: Uint8Array } = {},
  ) {
    this.ratchet = ratchet;
    this.theirIdentityKey = theirIdentityKey;
    if (options.pendingPreKey) this.pendingPreKey = options.pendingPreKey;
    if (options.theirBaseKey) this.theirBaseKey = options.theirBaseKey;
  }

  serialize(): string {
    const data: SessionRecordData = {
      version: 1,
      ratchet: this.ratchet.serialize(),
      theirIdentityKey: bytesToBase64(this.theirIdentityKey),
      ...(this.pendingPreKey && { pendingPreKey: this.pendingPreKey }),
      ...(this.theirBaseKey && { theirBaseKey: bytesToBase64(this.theirBaseKey) }),
    };
    return JSON.stringify(data);
  }

  static deserialize(serialized: string): SessionRecord {
    const data = JSON.parse(serialized) as SessionRecordData;
    if (data.version !== 1) throw new Error(`Unsupported session record version: ${data.version}`);
    return new SessionRecord(
      DoubleRatchet.deserialize(data.ratchet),
      base64ToBytes(data.theirIdentityKey),
      {
        ...(data.pendingPreKey && { pendingPreKey: data.pendingPreKey }),
        ...(data.theirBaseKey && { theirBaseKey: base64ToBytes(data.theirBaseKey) }),
      },
    );
  }
}
