# @up4it/signal-protocol

Clean-room TypeScript implementation of the **Signal Protocol** — X3DH,
Double Ratchet, Sender Keys (groups) — written from the public-domain
specifications at <https://signal.org/docs/>.

> Developed inside `react-chat-app` (Phase 1), to be extracted to its own
> repo and published on npm (Phase 3). See `BRIEF.md` at the repo root for
> the full plan.

## Status

- ✅ Phase 1: core crypto, X3DH, Double Ratchet, sessions, store, facade —
  implemented and covered by the Vitest suite (`npm test`).
- ✅ Backend key-server endpoints + WS relay (`backend/`, PostgreSQL) and
  HTTP `KeyServerClient` (`src/services/http-key-server.ts`) — verified
  end-to-end with two isolated clients.
- ✅ Phase 2: Sender Keys — per-sender chains with identity-signed SKDMs,
  per-message Ed25519 signatures, multi-state `SenderKeyRecord` (rotation
  keeps old chains decryptable, FIFO max 5) and skipped message keys for
  out-of-order delivery (FIFO cap 2000, max forward jump 25 000).

## Legal / provenance

- **License: Apache-2.0** (see [LICENSE](./LICENSE)).
- Implemented **from scratch** from the Signal specifications, each of which
  states: *"This document is hereby placed in the public domain."*
- **No code** was copied, ported or translated from `libsignal` (AGPL-3.0),
  `libsignal-protocol-javascript` (GPL-3.0, archived), or any other
  GPL/AGPL implementation.
- "Signal Protocol" is used descriptively; this project is not affiliated
  with or endorsed by Signal Messenger LLC.

## Constraints

- **Framework-agnostic**: no React, Angular, DOM or Node-specific imports.
  App glue (localStorage dummy server, UI naming) lives in
  `src/services/signal-gateway.ts`, outside this module.
- **Browser/WebView-safe**: pure TypeScript, no native bindings.
- Crypto primitives exclusively from [`@noble/curves`](https://github.com/paulmillr/noble-curves),
  [`@noble/hashes`](https://github.com/paulmillr/noble-hashes),
  [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) (pinned v2.2.0).
- AEAD is **AES-256-GCM-SIV** (misuse-resistant, RFC 8452), not plain GCM.

## Layout

```
core/         constants, @noble wrappers (DH, HKDF, HMAC, AEAD, sign/verify), utils, types
identity/     Ed25519 identity + Montgomery conversion, key generation helpers
x3dh/         X3DH key agreement: initiator, responder, prekey bundle
ratchet/      Double Ratchet: KDF chains, header, message AEAD, state machine
session/      prekey message envelope, session record/builder/cipher
sender-keys/  Sender Keys: state, multi-state record, SKDM, group cipher
store/        SignalProtocolStore interface + in-memory implementation
index.ts      public API: SignalProtocolManager facade + KeyServerClient contract
```

## Design decisions (vs. the specs)

- HKDF info strings are ours (`Up4itX3DH_v1`, `Up4itRatchet_v1`,
  `Up4itMessageKeys_v1`) — deliberately NOT wire-compatible with Signal.
- Identity keys are Ed25519; DH uses their Montgomery (X25519) form via
  `ed25519.utils.toMontgomery` / `toMontgomerySecret` (replaces XEdDSA,
  as libsignal does in practice).
- Message keys expand to AEAD key + deterministic nonce via HKDF; each
  message key encrypts exactly one message.
- Trust model: TOFU (trust-on-first-use); an identity key change makes
  session establishment fail until the app clears the stored identity.
- Concurrent session initiation (both sides initiate simultaneously) is
  resolved with a deterministic tie-break — the LOWER X3DH base key wins on
  both sides, so the pair converges on one session; the loser's first
  payload is lost and surfaced as a decrypt error. Sesame replaces this in
  a future phase.
- Sender key rotation ADDS a chain to the sender's record instead of
  replacing it, so in-flight messages survive the transition; chains are
  evicted FIFO beyond 5. A replayed (legitimately signed) old SKDM can
  re-add an evicted chain, making already-seen messages re-deliverable —
  same trade-off as libsignal, acceptable because SKDMs are identity-signed.

## @noble v2 API notes (differ from v1 docs and BRIEF §6)

- Import paths need the `.js` suffix (strict `exports` map):
  `@noble/curves/ed25519.js`, `@noble/hashes/hkdf.js`, `@noble/hashes/sha2.js`,
  `@noble/ciphers/aes.js`, `@noble/ciphers/utils.js`.
- Edwards→Montgomery: `ed25519.utils.toMontgomery(pub)` /
  `ed25519.utils.toMontgomerySecret(priv)` (v1's `edwardsToMontgomeryPub/Priv`
  no longer exist).
- Key generation: `x25519.keygen()` / `ed25519.keygen()` return
  `{ secretKey, publicKey }`.
- AES-GCM-SIV: `gcmsiv(key, nonce, aad?).encrypt/decrypt`.
