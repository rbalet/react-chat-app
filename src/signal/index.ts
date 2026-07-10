/**
 * @up4it/signal-protocol
 *
 * Clean-room TypeScript implementation of the Signal Protocol
 * (X3DH + Double Ratchet + Sender Keys), based solely on the
 * public-domain specifications at https://signal.org/docs/.
 *
 * Framework-agnostic: this module must never import React, Angular,
 * or any other UI framework. Crypto primitives come exclusively from
 * @noble/curves, @noble/hashes and @noble/ciphers.
 *
 * License: Apache-2.0 (see LICENSE in this directory).
 *
 * Module layout (see BRIEF.md §10):
 *   core/         @noble wrappers, utils, shared types
 *   identity/     identity key pair + key helper
 *   x3dh/         X3DH key agreement (initiator, responder, prekey bundle)
 *   ratchet/      Double Ratchet state machine
 *   session/      session builder / cipher / record
 *   sender-keys/  group messaging (Phase 2)
 *   store/        store interface + in-memory implementation
 *
 * Public API (implemented in Phase 1):
 *   export { SignalProtocolManager } from './manager';
 */

export const SIGNAL_PROTOCOL_VERSION = '0.0.0';
