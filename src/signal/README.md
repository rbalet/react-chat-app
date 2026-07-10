# @up4it/signal-protocol

Clean-room TypeScript implementation of the **Signal Protocol** — X3DH,
Double Ratchet and Sender Keys — written from the public-domain
specifications published at <https://signal.org/docs/>.

> Developed inside `react-chat-app` (Phase 1), to be extracted to its own
> repo and published on npm (Phase 3). See `BRIEF.md` at the repo root for
> the full plan.

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

- **Framework-agnostic**: no React, Angular or other framework imports.
- **Browser/WebView-safe**: pure TypeScript, no native bindings.
- Crypto primitives exclusively from [`@noble/curves`](https://github.com/paulmillr/noble-curves),
  [`@noble/hashes`](https://github.com/paulmillr/noble-hashes),
  [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers).
- AEAD is **AES-GCM-SIV** (misuse-resistant), not plain AES-GCM.

## Layout

```
core/         @noble wrappers (DH, HKDF, HMAC, AEAD, sign/verify), utils, types
identity/     Ed25519 identity key pair + Montgomery conversion, key helper
x3dh/         X3DH key agreement: initiator, responder, prekey bundle
ratchet/      Double Ratchet: state machine, chains, header, message
session/      session builder (X3DH → ratchet init), session cipher, session record
sender-keys/  group messaging via Sender Keys (Phase 2)
store/        SignalProtocolStore interface + in-memory implementation
index.ts      public API: SignalProtocolManager facade
```

## @noble v2 API notes (differs from older docs)

- `x25519`, `ed25519`: `import { x25519, ed25519 } from '@noble/curves/ed25519'`
- Edwards→Montgomery conversion: `ed25519.utils.toMontgomery(pub)` and
  `ed25519.utils.toMontgomerySecret(priv)` (the v1 helpers
  `edwardsToMontgomeryPub/Priv` no longer exist).
- AES-GCM-SIV: `import { gcmsiv } from '@noble/ciphers/aes'`
- HKDF/HMAC/SHA-256: `@noble/hashes/hkdf`, `@noble/hashes/hmac`,
  `@noble/hashes/sha2`
