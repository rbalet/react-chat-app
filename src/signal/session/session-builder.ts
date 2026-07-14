/**
 * Session builder: orchestrates X3DH → Double Ratchet initialization on
 * both sides (initiator from a prekey bundle, responder from an incoming
 * prekey message).
 *
 * Sesame-style concurrent-initiation resolution is out of scope for
 * Phase 1 (single device, 1:1): a newly processed handshake simply
 * replaces any existing session with that peer.
 */

import { x3dhInitiate } from '../x3dh/initiator';
import { x3dhRespond } from '../x3dh/responder';
import { DoubleRatchet } from '../ratchet/ratchet';
import { bytesToBase64 } from '../core/utils';
import { SessionRecord } from './session-record';
import type { PreKeyMessage } from './prekey-message';
import type { PreKeyBundle } from '../core/types';
import type { SignalProtocolStore } from '../store/store-interface';

async function requireLocalIdentity(store: SignalProtocolStore) {
  const identity = await store.getIdentityKeyPair();
  const registrationId = await store.getLocalRegistrationId();
  if (!identity || registrationId === undefined) {
    throw new Error('Local identity not initialized — call SignalProtocolManager.initialize()');
  }
  return { identity, registrationId };
}

/**
 * Initiator (Alice): verify + consume the peer's prekey bundle, derive SK,
 * initialize the ratchet toward their signed prekey, and persist a session
 * carrying the pending handshake data.
 */
export async function startSession(
  store: SignalProtocolStore,
  remoteUserId: string,
  bundle: PreKeyBundle,
): Promise<SessionRecord> {
  const { identity, registrationId } = await requireLocalIdentity(store);

  if (!(await store.isTrustedIdentity(remoteUserId, bundle.identityKey))) {
    throw new Error(`Untrusted identity key change for ${remoteUserId}`);
  }

  const { sharedKey, ephemeralKey, associatedData } = x3dhInitiate(identity, bundle);
  const ratchet = DoubleRatchet.initAlice(
    sharedKey,
    bundle.signedPreKey.publicKey,
    associatedData,
  );

  const record = new SessionRecord(ratchet, bundle.identityKey, {
    pendingPreKey: {
      registrationId,
      signedPreKeyId: bundle.signedPreKey.id,
      ...(bundle.oneTimePreKey && { preKeyId: bundle.oneTimePreKey.id }),
      baseKey: bytesToBase64(ephemeralKey.publicKey),
    },
  });

  await store.saveRemoteIdentity(remoteUserId, bundle.identityKey);
  await store.storeSession(remoteUserId, record.serialize());
  return record;
}

/**
 * Responder (Bob): recompute SK from an incoming prekey message using our
 * signed/one-time prekey private halves, and initialize the ratchet with
 * the signed prekey as initial ratchet key.
 *
 * Returns an UNCOMMITTED record: the caller (session cipher) must decrypt
 * the embedded message first, then call `commitResponderSession` — so a
 * forged handshake never burns a one-time prekey or stores broken state.
 */
export async function buildResponderSession(
  store: SignalProtocolStore,
  remoteUserId: string,
  message: PreKeyMessage,
): Promise<SessionRecord> {
  const { identity } = await requireLocalIdentity(store);

  if (!(await store.isTrustedIdentity(remoteUserId, message.identityKey))) {
    throw new Error(`Untrusted identity key change for ${remoteUserId}`);
  }

  const signedPreKey = await store.loadSignedPreKey(message.signedPreKeyId);
  if (!signedPreKey) {
    throw new Error(`Unknown signed prekey id ${message.signedPreKeyId}`);
  }

  let oneTimePreKey;
  if (message.preKeyId !== undefined) {
    oneTimePreKey = await store.loadOneTimePreKey(message.preKeyId);
    if (!oneTimePreKey) {
      throw new Error(`One-time prekey ${message.preKeyId} not found (already consumed?)`);
    }
  }

  const { sharedKey, associatedData } = x3dhRespond(
    identity,
    signedPreKey.keyPair,
    oneTimePreKey?.keyPair,
    message.identityKey,
    message.baseKey,
  );
  const ratchet = DoubleRatchet.initBob(sharedKey, signedPreKey.keyPair, associatedData);

  return new SessionRecord(ratchet, message.identityKey, { theirBaseKey: message.baseKey });
}

/** Persist a responder session after its first message decrypted successfully. */
export async function commitResponderSession(
  store: SignalProtocolStore,
  remoteUserId: string,
  record: SessionRecord,
  consumedPreKeyId: number | undefined,
): Promise<void> {
  await store.saveRemoteIdentity(remoteUserId, record.theirIdentityKey);
  if (consumedPreKeyId !== undefined) {
    await store.removeOneTimePreKey(consumedPreKeyId);
  }
  await store.storeSession(remoteUserId, record.serialize());
}
