/**
 * SenderKeyRecord — the multi-state container stored per (groupId, senderId).
 *
 * Rotation must not cut off messages already in flight under the previous
 * chain: a rotation ADDS a fresh state instead of replacing the old one, and
 * decryption looks the state up by the message's distributionId (which plays
 * the role of libsignal's chain_id — one unique id per chain). Old states
 * are evicted FIFO beyond MAX_SENDER_KEY_STATES, mirroring libsignal's
 * five-state SenderKeyRecord.
 */

import { SenderKeyState, type SerializedSenderKeyState } from './sender-key-state';

export const MAX_SENDER_KEY_STATES = 5;

export interface SerializedSenderKeyRecord {
  version: 1;
  /** Oldest → newest; encrypt always uses the newest. */
  states: SerializedSenderKeyState[];
}

export class SenderKeyRecord {
  constructor(private readonly states: SenderKeyState[]) {}

  /** Fresh record with a single brand-new state. */
  static create(): SenderKeyRecord {
    return new SenderKeyRecord([SenderKeyState.create()]);
  }

  /** The newest state — the one encrypt() must use. */
  current(): SenderKeyState {
    const state = this.states[this.states.length - 1];
    if (!state) throw new Error('SenderKeyRecord has no states');
    return state;
  }

  /** Look a chain up by its distributionId (any state, not just the newest). */
  find(distributionId: string): SenderKeyState | undefined {
    return this.states.find((s) => s.distributionId === distributionId);
  }

  /** Append a state (newest); evict the oldest beyond MAX_SENDER_KEY_STATES. */
  add(state: SenderKeyState): void {
    this.states.push(state);
    while (this.states.length > MAX_SENDER_KEY_STATES) {
      this.states.shift();
    }
  }

  /** Number of live states (mostly for tests/diagnostics). */
  size(): number {
    return this.states.length;
  }

  serialize(): SerializedSenderKeyRecord {
    return { version: 1, states: this.states.map((s) => s.serialize()) };
  }

  static deserialize(data: SerializedSenderKeyRecord | SerializedSenderKeyState): SenderKeyRecord {
    // Legacy compatibility: a pre-record store held a single bare state.
    if (!('states' in data)) {
      return new SenderKeyRecord([SenderKeyState.deserialize(data)]);
    }
    if (data.version !== 1) {
      throw new Error(`Unknown SenderKeyRecord version ${(data as { version: number }).version}`);
    }
    return new SenderKeyRecord(data.states.map((s) => SenderKeyState.deserialize(s)));
  }
}
