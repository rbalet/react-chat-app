/**
 * In-memory SignalProtocolStore — reference implementation for tests and
 * the PoC. Not persistent: a page reload loses all sessions and keys.
 */

import { equalBytes } from '../core/utils';
import type { IdentityKeyPair, OneTimePreKeyPair, SignedPreKeyPair } from '../core/types';
import type { SignalProtocolStore } from './store-interface';

export class InMemorySignalProtocolStore implements SignalProtocolStore {
  private identityKeyPair: IdentityKeyPair | undefined;
  private registrationId: number | undefined;
  private readonly remoteIdentities = new Map<string, Uint8Array>();
  private readonly signedPreKeys = new Map<number, SignedPreKeyPair>();
  private readonly oneTimePreKeys = new Map<number, OneTimePreKeyPair>();
  private readonly sessions = new Map<string, string>();
  private readonly senderKeys = new Map<string, Map<string, string>>();

  async getIdentityKeyPair(): Promise<IdentityKeyPair | undefined> {
    return this.identityKeyPair;
  }

  async storeIdentityKeyPair(keyPair: IdentityKeyPair): Promise<void> {
    this.identityKeyPair = keyPair;
  }

  async getLocalRegistrationId(): Promise<number | undefined> {
    return this.registrationId;
  }

  async storeLocalRegistrationId(registrationId: number): Promise<void> {
    this.registrationId = registrationId;
  }

  async getRemoteIdentity(userId: string): Promise<Uint8Array | undefined> {
    return this.remoteIdentities.get(userId);
  }

  async saveRemoteIdentity(userId: string, identityKeyEd: Uint8Array): Promise<boolean> {
    const existing = this.remoteIdentities.get(userId);
    this.remoteIdentities.set(userId, identityKeyEd);
    return existing !== undefined && !equalBytes(existing, identityKeyEd);
  }

  async isTrustedIdentity(userId: string, identityKeyEd: Uint8Array): Promise<boolean> {
    const existing = this.remoteIdentities.get(userId);
    return existing === undefined || equalBytes(existing, identityKeyEd);
  }

  async storeSignedPreKey(signedPreKey: SignedPreKeyPair): Promise<void> {
    this.signedPreKeys.set(signedPreKey.id, signedPreKey);
  }

  async loadSignedPreKey(id: number): Promise<SignedPreKeyPair | undefined> {
    return this.signedPreKeys.get(id);
  }

  async storeOneTimePreKey(preKey: OneTimePreKeyPair): Promise<void> {
    this.oneTimePreKeys.set(preKey.id, preKey);
  }

  async loadOneTimePreKey(id: number): Promise<OneTimePreKeyPair | undefined> {
    return this.oneTimePreKeys.get(id);
  }

  async removeOneTimePreKey(id: number): Promise<void> {
    this.oneTimePreKeys.delete(id);
  }

  async storeSession(userId: string, record: string): Promise<void> {
    this.sessions.set(userId, record);
  }

  async loadSession(userId: string): Promise<string | undefined> {
    return this.sessions.get(userId);
  }

  async removeSession(userId: string): Promise<void> {
    this.sessions.delete(userId);
  }

  async storeSenderKey(groupId: string, senderId: string, state: string): Promise<void> {
    if (!this.senderKeys.has(groupId)) this.senderKeys.set(groupId, new Map());
    this.senderKeys.get(groupId)!.set(senderId, state);
  }

  async loadSenderKey(groupId: string, senderId: string): Promise<string | undefined> {
    return this.senderKeys.get(groupId)?.get(senderId);
  }
}
