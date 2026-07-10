/**
 * Session cipher: the public encrypt/decrypt API over an established (or
 * establishing) session with one peer.
 *
 * Encrypt: while the session still has pending handshake data, messages
 * are wrapped in a PreKey envelope (X3DH §3.3 — Alice keeps including the
 * handshake until Bob replies). Afterwards, plain SignalMessages.
 *
 * Decrypt: PreKey envelopes bootstrap the responder session (idempotently
 * for duplicates); Signal envelopes go straight to the ratchet.
 *
 * Concurrency contract: operations are read-modify-write on the stored
 * session record. Callers MUST NOT run two operations for the same peer
 * concurrently — SignalProtocolManager serializes them per peer; direct
 * users of this class must do the same.
 */

import { MessageType, type EncryptedMessage } from '../core/types';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToUtf8,
  compareBytes,
  equalBytes,
  utf8ToBytes,
} from '../core/utils';
import { SessionRecord } from './session-record';
import {
  parsePreKeyMessage,
  serializePreKeyMessage,
} from './prekey-message';
import { buildResponderSession, commitResponderSession } from './session-builder';
import type { SignalProtocolStore } from '../store/store-interface';

export class SessionCipher {
  constructor(
    private readonly store: SignalProtocolStore,
    private readonly remoteUserId: string,
  ) {}

  async hasSession(): Promise<boolean> {
    return (await this.store.loadSession(this.remoteUserId)) !== undefined;
  }

  async encrypt(plaintext: string): Promise<EncryptedMessage> {
    const record = await this.loadRecord();
    const message = record.ratchet.encrypt(utf8ToBytes(plaintext));

    let envelope: EncryptedMessage;
    if (record.pendingPreKey) {
      const identity = await this.store.getIdentityKeyPair();
      if (!identity) throw new Error('Local identity not initialized');
      const pending = record.pendingPreKey;
      envelope = {
        type: MessageType.PreKey,
        body: bytesToBase64(
          serializePreKeyMessage({
            registrationId: pending.registrationId,
            signedPreKeyId: pending.signedPreKeyId,
            ...(pending.preKeyId !== undefined && { preKeyId: pending.preKeyId }),
            identityKey: identity.ed.publicKey,
            baseKey: base64ToBytes(pending.baseKey),
            message,
          }),
        ),
      };
    } else {
      envelope = { type: MessageType.Signal, body: bytesToBase64(message) };
    }

    await this.store.storeSession(this.remoteUserId, record.serialize());
    return envelope;
  }

  async decrypt(envelope: EncryptedMessage): Promise<string> {
    switch (envelope.type) {
      case MessageType.PreKey:
        return this.decryptPreKeyMessage(base64ToBytes(envelope.body));
      case MessageType.Signal:
        return this.decryptSignalMessage(base64ToBytes(envelope.body));
      default:
        throw new Error(`Unknown message type: ${(envelope as EncryptedMessage).type}`);
    }
  }

  private async decryptPreKeyMessage(bytes: Uint8Array): Promise<string> {
    const preKeyMessage = parsePreKeyMessage(bytes);

    // Duplicate/parallel prekey messages for a session we already built:
    // reuse the existing ratchet instead of re-running X3DH (the one-time
    // prekey is already gone, and rebuilding would fork the session).
    // The identity must match too — a mismatch falls through to the
    // regular path, where the TOFU check rejects it with a clear error.
    const existing = await this.tryLoadRecord();
    if (
      existing?.theirBaseKey &&
      equalBytes(existing.theirBaseKey, preKeyMessage.baseKey) &&
      equalBytes(existing.theirIdentityKey, preKeyMessage.identityKey)
    ) {
      const plaintext = existing.ratchet.decrypt(preKeyMessage.message);
      await this.store.storeSession(this.remoteUserId, existing.serialize());
      return bytesToUtf8(plaintext);
    }

    // Concurrent initiation: both sides sent a handshake before seeing the
    // other's. Each would otherwise adopt the peer's session and abandon its
    // own — two forked sessions that can never decrypt each other. Applying
    // the same deterministic rule on both sides (LOWER base key wins) makes
    // exactly one handshake survive: the loser's first payload is lost (the
    // sender keeps re-sending its own handshake envelope, which the other
    // side accepts), and both converge on the winner's session.
    if (existing?.pendingPreKey) {
      const ourBaseKey = base64ToBytes(existing.pendingPreKey.baseKey);
      if (compareBytes(preKeyMessage.baseKey, ourBaseKey) > 0) {
        throw new Error(
          'Concurrent session initiation: our handshake wins the tie-break, rejecting theirs',
        );
      }
    }

    const record = await buildResponderSession(this.store, this.remoteUserId, preKeyMessage);
    // Decrypt BEFORE committing: a forged handshake must not consume the
    // one-time prekey, replace an existing session, or record an identity.
    const plaintext = record.ratchet.decrypt(preKeyMessage.message);
    await commitResponderSession(this.store, this.remoteUserId, record, preKeyMessage.preKeyId);
    return bytesToUtf8(plaintext);
  }

  private async decryptSignalMessage(bytes: Uint8Array): Promise<string> {
    const record = await this.loadRecord();
    const plaintext = record.ratchet.decrypt(bytes);
    // Any authenticated inbound message proves the peer has the session:
    // stop sending the (now redundant) handshake envelope.
    delete record.pendingPreKey;
    await this.store.storeSession(this.remoteUserId, record.serialize());
    return bytesToUtf8(plaintext);
  }

  private async loadRecord(): Promise<SessionRecord> {
    const record = await this.tryLoadRecord();
    if (!record) throw new Error(`No session with ${this.remoteUserId}`);
    return record;
  }

  private async tryLoadRecord(): Promise<SessionRecord | undefined> {
    const serialized = await this.store.loadSession(this.remoteUserId);
    return serialized === undefined ? undefined : SessionRecord.deserialize(serialized);
  }
}
