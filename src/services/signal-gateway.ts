/**
 * App-level glue between the React UI and the signal-protocol module.
 * Keeps the legacy method names (initializeAsync / encryptMessageAsync /
 * decryptMessageAsync) so chatWindow.jsx stays unchanged.
 *
 * This file is deliberately OUTSIDE src/signal/: the module stays
 * framework/environment-agnostic; browser specifics (fetch) and
 * UI-facing naming live here.
 */

import {
  InMemorySignalProtocolStore,
  SignalProtocolManager,
  type EncryptedMessage,
} from '../signal';
import { HttpKeyServer } from './http-key-server';

/** Legacy-named facade over SignalProtocolManager for the existing UI. */
export class SignalGatewayManager {
  private readonly manager: SignalProtocolManager;

  constructor(userId: string, server?: HttpKeyServer) {
    this.manager = new SignalProtocolManager(
      userId,
      new InMemorySignalProtocolStore(),
      server ?? new HttpKeyServer(),
    );
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
  server?: HttpKeyServer,
): Promise<SignalGatewayManager> {
  const manager = new SignalGatewayManager(userId, server);
  await manager.initializeAsync();
  return manager;
}
