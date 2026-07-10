/**
 * App-level glue between the React UI and the signal-protocol module.
 * Keeps the legacy method names (initializeAsync / encryptMessageAsync /
 * decryptMessageAsync) so chatWindow.jsx stays unchanged.
 *
 * This file is deliberately OUTSIDE src/signal/: the module stays
 * framework/environment-agnostic; browser specifics (localStorage) and
 * UI-facing naming live here.
 */

import {
  InMemorySignalProtocolStore,
  SignalProtocolManager,
  type EncryptedMessage,
  type KeyServerClient,
  type PublishedKeys,
  type SerializedPreKeyBundle,
} from '../signal';

const STORAGE_PREFIX = 'signal-published-keys:';

/**
 * Dummy key server backed by localStorage — shared across tabs of the same
 * origin, so two tabs can chat without a real backend. The production
 * implementation will hit POST/GET /keys/:userId instead (BRIEF.md §9).
 */
export class SignalServerStore implements KeyServerClient {
  async publishKeys(userId: string, keys: PublishedKeys): Promise<void> {
    localStorage.setItem(STORAGE_PREFIX + userId, JSON.stringify(keys));
  }

  async fetchPreKeyBundle(userId: string): Promise<SerializedPreKeyBundle> {
    const raw = localStorage.getItem(STORAGE_PREFIX + userId);
    if (!raw) throw new Error(`No published keys for user ${userId}`);
    const keys = JSON.parse(raw) as PublishedKeys;

    // Consume one one-time prekey, like the real server must do atomically.
    const oneTimePreKey = keys.oneTimePreKeys.shift();
    localStorage.setItem(STORAGE_PREFIX + userId, JSON.stringify(keys));

    return {
      registrationId: keys.registrationId,
      identityKey: keys.identityKey,
      signedPreKey: keys.signedPreKey,
      ...(oneTimePreKey && { oneTimePreKey }),
    };
  }
}

/** Legacy-named facade over SignalProtocolManager for the existing UI. */
export class SignalGatewayManager {
  private readonly manager: SignalProtocolManager;

  constructor(userId: string, server: SignalServerStore) {
    // In-memory store: identity and sessions last for the page's lifetime,
    // exactly like the original PoC. Persistence comes with the backend
    // integration (password-derived key backup, BRIEF.md §7).
    this.manager = new SignalProtocolManager(userId, new InMemorySignalProtocolStore(), server);
  }

  async initializeAsync(): Promise<void> {
    await this.manager.initialize();
  }

  async encryptMessageAsync(remoteUserId: string, message: string): Promise<EncryptedMessage> {
    return this.manager.encryptMessage(remoteUserId, message);
  }

  async decryptMessageAsync(remoteUserId: string, cipherText: EncryptedMessage): Promise<string> {
    return this.manager.decryptMessage(remoteUserId, cipherText);
  }
}

export async function createSignalProtocolManager(
  userId: string,
  _userName: string,
  server: SignalServerStore,
): Promise<SignalGatewayManager> {
  const manager = new SignalGatewayManager(userId, server);
  await manager.initializeAsync();
  return manager;
}
