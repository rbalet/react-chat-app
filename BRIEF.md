# BRIEF — Signal Protocol Implementation in TypeScript

> This document is the single source of truth for the project.
> Any developer or AI agent picking up this work should read this document
> in full before writing any code.

---

## 1. Context

**up4it** is an Ionic/Angular + NestJS chat application with an existing v1
end-to-end encryption system (shared AES-256 group key, manual rotation on
member departure). The team wants to migrate to the **Signal Protocol** — the
industry standard used by WhatsApp, Signal, Google Messages, and others — for
forward secrecy, post-compromise security, and alignment with European
messaging standards.

### Why not use the official libsignal library?

1. **Browser incompatibility**: `@signalapp/libsignal-client` is a Rust binary
   with N-API Node.js bindings. It works in Node.js and Electron, but NOT in a
   browser WebView. Ionic/Capacitor apps run in a WebView — native addons
   cannot load.

2. **License**: libsignal is **AGPL-3.0**. Using it in a proprietary app would
   force open-sourcing the entire application (AGPL copyleft extends to the
   whole combined work upon distribution, and Section 13 adds a network-use
   trigger).

### The solution

Implement the Signal Protocol **from scratch** in TypeScript, based on the
**public-domain specifications**. This is exactly what WhatsApp, Google, and
Facebook did — they wrote their own implementations from the spec, not using
the AGPL library.

---

## 2. Legal Foundation

### The specifications are public domain

All Signal Protocol specifications contain an explicit public-domain dedication.
The verbatim text, found in the "IPR" section of each spec:

> "This document is hereby placed in the public domain."

Verified for all six specifications at https://signal.org/docs/:

| Specification | IPR Section | Text |
|---|---|---|
| X3DH | §5 | "This document is hereby placed in the public domain." |
| Double Ratchet | §9 | "This document is hereby placed in the public domain." |
| PQXDH | §5 | "This document is hereby placed in the public domain." |
| Sesame | §7 | "This document is hereby placed in the public domain." |
| XEdDSA and VXEdDSA | §9 | "This document is hereby placed in the public domain." |
| ML-KEM Braid | §4 | "This document is hereby placed in the public domain." |

**Note on Sender Keys**: There is NO standalone "Sender Keys" specification on
signal.org. Group messaging is documented in the WhatsApp Security Whitepaper
and academic literature (ASIACRYPT 2023, "WhatsUpp with Sender Keys"). The
algorithm itself is not copyrightable; implement from the algorithmic
description in academic sources, not from proprietary whitepaper text.

### Clean-room constraint

This MUST be a clean-room implementation:

- ✅ READ the public-domain specs at signal.org/docs and implement from the
  algorithmic descriptions.
- ✅ READ other implementations (e.g., `@privacyresearch/libsignal-protocol-typescript`)
  for understanding patterns and API design.
- ❌ Do NOT copy, port, or translate code from `libsignal` (AGPL-3.0).
- ❌ Do NOT copy code from any GPL-licensed library.
- ❌ Do NOT copy code from the old `libsignal-protocol-javascript` (archived, GPL-3.0).

A translation/port of AGPL code is a derivative work and must stay AGPL.
A from-scratch implementation based on the public-domain spec is your own
original work and can be licensed however you choose.

### No known patents

No Signal/Open Whisper Systems patents are known to exist or be enforced on
these protocols. The broad pattern of unlicensed third-party implementations
(Meta/WhatsApp, Google, Microsoft, Viber, Wire, Matrix, Session) strongly
supports the conclusion that the protocol is freely implementable.

### Trademark note

Do NOT name the product "Signal" or use Signal logos. "Signal Protocol" is
a descriptive term (like "HTTP"). Call the library something independent
(e.g., `@up4it/signal-protocol`).

---

## 3. License

**Apache-2.0**

- Permissive: allows use in proprietary apps without open-sourcing them.
- Includes an explicit patent grant (important for crypto libraries — protects
  against patent trolls).
- Standard choice for security libraries (libsodium, rustls, etc.).
- MIT is simpler but lacks the patent clause — Apache-2.0 is preferred for crypto.

---

## 4. Architecture

### Three-repo strategy

```
┌─────────────────────────────────────────────────────────────┐
│  @up4it/signal-protocol (to be created, Apache-2.0)         │
│                                                             │
│  Pure TypeScript library (npm package)                     │
│  X3DH + Double Ratchet + Sender Keys                       │
│  Zero framework dependencies (no React, no Angular)        │
│  Depends on: @noble/curves, @noble/hashes, @noble/ciphers  │
│                                                             │
│  → Usable by anyone, anywhere                              │
└──────────────────────┬──────────────────────────────────────┘
                       │ (npm install)
          ┌────────────┴────────────┐
          ▼                         ▼
┌──────────────────┐    ┌──────────────────────────┐
│  react-chat-app   │    │  up4it (proprietary)     │
│  (open-source)    │    │                          │
│                   │    │  Angular/Ionic app       │
│  PoC React        │    │  NestJS + PostgreSQL     │
│  Demo + tests     │    │                          │
│  Backend Express  │    │  Production app          │
│                   │    │  Replaces v1 crypto      │
│  Reference + demo │    │                          │
└──────────────────┘    └──────────────────────────┘
```

### Development order

1. **Phase 1**: Develop the module INSIDE `react-chat-app` (in `src/signal/`),
   structured as framework-agnostic TypeScript.
2. **Phase 2**: When stable and tested, extract to its own repo
   (`the-corner-inc/signal-protocol`) and publish on npm.
3. **Phase 3**: Integrate into up4it (Angular/Ionic) as an npm dependency.

No separate "Angular PoC" repo needed — the module is framework-agnostic, so
Angular integration is just a thin service wrapper in up4it.

---

## 5. Protocol specifications to implement

### Phase 1 — Core (1:1 messaging)

**X3DH** (Extended Triple Diffie-Hellman) — async key agreement with prekeys.
- Spec: https://signal.org/docs/specifications/x3dh/
- Alice fetches Bob's prekey bundle (identity key + signed prekey + one-time
  prekey) from the server, computes DH1-DH4, derives a shared secret SK.
- Bob derives the same SK when he receives Alice's first message.
- The one-time prekey is consumed atomically by the server (DELETE on fetch).

**Double Ratchet** — per-message forward secrecy + post-compromise security.
- Spec: https://signal.org/docs/specifications/doubleratchet/
- After X3DH establishes SK, each message uses a fresh key derived from a
  ratcheting chain (KDF chains + DH ratchet).
- Forward secrecy: compromising current keys doesn't reveal past messages.
- Post-compromise security: the DH ratchet heals after a compromise.

### Phase 2 — Groups

**Sender Keys** — group messaging with per-sender forward secrecy.
- No standalone spec on signal.org; documented in WhatsApp Security Whitepaper
  and academic literature.
- Each sender has their own chain (chainKey + signingKey) per group.
- SenderKeyDistributionMessage (SKDM) sent to each member via 1:1 sessions.
- One ciphertext per message (not N encryptions).
- Member departure: the leaver's chain is rotated; other senders' chains are
  unaffected — NO history loss (unlike the v1 shared-key rotation).

### Future phases (document but do not implement yet)

**Sesame** — multi-device session management.
- Spec: https://signal.org/docs/specifications/sesame/
- Manages sessions across multiple devices per user.
- The PoC starts with 1 device per user. Sesame can be added later.

**PQXDH** — post-quantum key agreement.
- Spec: https://signal.org/docs/specifications/pqxdh/
- Adds ML-KEM (Kyber) to X3DH for quantum resistance.
- Requires `@noble/post-quantum` (separate npm package).
- Current libsignal mandates PQXDH, but it's optional per the spec.
- Can be added as an upgrade path without breaking existing sessions.

---

## 6. Crypto primitives — @noble compatibility

The @noble library family (already used in the up4it v1) provides every
classical primitive the Signal Protocol needs. No new dependencies required
for Phase 1-2.

### Mapping table

| Signal requirement | @noble function | Package | Compatible? |
|---|---|---|---|
| X25519 DH | `x25519.getSharedSecret(priv, pub)`, `x25519.getPublicKey(priv)` | `@noble/curves` | ✅ YES |
| Ed25519 signatures | `ed25519.sign(priv, msg)`, `ed25519.verify(pub, msg, sig)`, `ed25519.getPublicKey(priv)` | `@noble/curves` | ✅ YES |
| Edwards→Montgomery conversion | `edwardsToMontgomeryPub(pub)`, `edwardsToMontgomeryPriv(priv)` | `@noble/curves` | ✅ YES |
| HKDF-SHA256 | `hkdf(sha256, ikm, salt, info, length)` | `@noble/hashes` | ✅ YES |
| HMAC-SHA256 | `hmac(sha256, key, data)` | `@noble/hashes` | ✅ YES |
| SHA-256 | `sha256(data)` | `@noble/hashes` | ✅ YES |
| AES-GCM-SIV (recommended AEAD) | `gcmsiv(key, nonce)` | `@noble/ciphers` | ✅ YES |
| AES-CBC + HMAC (alt AEAD) | `cbc(key, iv)` + `hmac(sha256, ...)` | `@noble/ciphers` + `@noble/hashes` | ✅ YES |
| ML-KEM / Kyber (PQXDH, future) | `ml_kem` | `@noble/post-quantum` | Needs extra dep |
| Random bytes | `randomBytes(length)` | `@noble/ciphers/utils` | ✅ YES |

### Key algorithm choices

- **DH curve**: X25519 (mandated by spec).
- **Signatures**: Ed25519 (the spec names XEdDSA, but libsignal actually uses
  Ed25519 in practice — @noble provides native Ed25519 + Edwards↔Montgomery
  conversion).
- **KDF**: HKDF-SHA256 (for root key + X3DH) and HMAC-SHA256 (for chain key
  ratchet).
- **AEAD**: **AES-GCM-SIV** (NOT plain AES-GCM). The spec recommends
  misuse-resistant AEAD. libsignal uses AES-GCM-SIV. `@noble/ciphers` provides
  `gcmsiv`. Plain GCM is NOT misuse-resistant and is discouraged for Double
  Ratchet message keys.

---

## 7. Design decisions

### HKDF info strings

The spec leaves info strings to the application (§2.1). Choose your own:

```
X3DH KDF:        info = "Up4itX3DH_v1"
KDF_RK:          info = "Up4itRatchet_v1"
Message keys:    info = "Up4itMessageKeys_v1"
```

These must be constant and distinct. Using different info strings from Signal
means the implementation is NOT wire-compatible with official Signal clients
— that's fine for a standalone protocol.

### X3DH F prefix

X3DH requires prepending `F` (32 bytes of `0xFF` for X25519) to the IKM before
HKDF, for domain separation. Easy to forget — must include.

### Chain key constants

KDF_CK uses HMAC-SHA256 with the chain key as the HMAC key:
- `HMAC(ck, 0x01)` → message key seed
- `HMAC(ck, 0x02)` → next chain key

These are byte-exact constants from the Double Ratchet spec.

### HKDF salt conventions

- X3DH KDF: salt = zero-filled bytes (hash output length)
- KDF_RK: salt = root key
- Message keys: salt = zero-filled bytes (or root key for PQ variant)

### Key backup: password-derived (no separate PIN)

The user's app password is used to derive a backup key:

```
1. User enters password to log in
2. Client derives: backupKey = Argon2id(password, salt_client, strong_params)
   - salt_client is DIFFERENT from the auth hash salt
   - params are STRONGER than the auth hash params (more memory, more iterations)
3. Client encrypts: encryptedPrivateKey = AES-GCM-SIV(backupKey, privateKey)
4. Client uploads { encryptedPrivateKey, salt, nonce } to the server
5. Client sends the auth hash to the server for authentication (separate path)
```

The server has: the auth hash + the encrypted blob. It CANNOT derive the
backup key because:
- The auth hash is irreversible (one-way function)
- The backup salt is different from the auth salt
- The backup KDF params are different

If the password changes: the client re-derives with the new password,
re-encrypts the private key, and re-uploads.

**Do NOT derive from userId** — it's public (stored in the DB next to the
blob, in API calls, in URLs). Deriving a key from a public value provides
zero security.

**Do NOT use a separate PIN** — the app password is sufficient and avoids
user friction. The user already enters it to log in.

---

## 8. What NOT to do

1. ❌ Do NOT copy code from `libsignal` (AGPL-3.0) — clean-room implementation only.
2. ❌ Do NOT copy code from `@privacyresearch/libsignal-protocol-typescript` (GPL-3.0) — read for patterns, do not copy.
3. ❌ Do NOT use native bindings (N-API, .node files, Rust binaries) — must work in browser/WebView.
4. ❌ Do NOT use the old `libsignal-protocol-javascript` (archived since Aug 2021, GPL-3.0, no security patches since 2018).
5. ❌ Do NOT derive backup key from userId (it's public — zero security).
6. ❌ Do NOT use plain AES-GCM for Double Ratchet messages (not misuse-resistant — use AES-GCM-SIV instead).
7. ❌ Do NOT name the product "Signal" or use Signal logos (trademark).
8. ❌ Do NOT import React, Angular, or any framework in the signal-protocol module — it must be framework-agnostic.

---

## 9. Current react-chat-app structure

The repo at `C:\Users\garam\Desktop\Documents\Developpeur\TheCorner\react-chat-app`
is a dormant (last commit April 2021) Create React App demo.

### What exists

```
react-chat-app/
├── package.json              # React 17, CRA 4, no TypeScript
├── public/
│   ├── index.html            # loads libsignal-protocol.js via <script> tag
│   └── libsignal-protocol.js # 1.46 MB vendored blob (OLD, deprecated, TO DELETE)
└── src/
    ├── App.js                # root: login state + creates SignalProtocolManager
    ├── components/
    │   ├── login/login.js
    │   └── chatWindow/
    │       ├── chatWindow.js # WS lifecycle + encrypt/decrypt orchestration
    │       ├── contactList.js
    │       └── messageBox.js
    ├── services/
    │   ├── api.js            # axios wrappers (logIn, getContacts)
    │   └── constants.js      # BASE_URL = http://localhost:4000/
    └── signal/
        ├── SignalGateway.js          # React↔libsignal glue (2 classes)
        ├── InMemorySignalProtocolStore.js  # implements libsignal's Store interface
        └── helpers.js                # ArrayBuffer/base64 utilities (uses dcodeIO.ByteBuffer)
```

### What to change

1. **Delete** `public/libsignal-protocol.js` (the 1.46 MB vendored old library).
2. **Remove** the `<script src="./libsignal-protocol.js">` line from `public/index.html`.
3. **Initialize TypeScript**: `tsc --init`, rename `.js` → `.ts` progressively.
4. **Install** `@noble/curves`, `@noble/hashes`, `@noble/ciphers`.
5. **Rewrite** `src/signal/` from scratch as a framework-agnostic TypeScript module.
6. **Keep** the `SignalProtocolManager` facade API (`initializeAsync`, `encryptMessageAsync`, `decryptMessageAsync`) so the UI layer barely changes.
7. **Port** the `InMemorySignalProtocolStore` to a TypeScript interface (it documents the store contract).
8. **Replace** `helpers.js` (which depends on `dcodeIO.ByteBuffer` from the old lib) with native TS utilities (TextEncoder, btoa/atob).

### Backend

The backend is a separate repo: `VertikaJain/node-express-ts-chat-app`
(Express + MongoDB + WebSocket relay). It currently has:
- `GET api/users/login/:userName` — returns User document
- `GET api/users/:userid/:role` — returns contacts
- WebSocket relay (stateless, no auth, no message storage)

**Missing** (must be added for Signal Protocol):
- `POST /keys/:userId` — register prekeys (identity, signed prekey, one-time prekeys)
- `GET /keys/:userId` — fetch prekey bundle (atomically consume one one-time prekey)
- `GET /keys/count/:userId` — prekey count (for replenishment)
- Message storage for offline delivery (optional for PoC — WebSocket relay may suffice)

---

## 10. Module structure (target)

```
src/signal/
├── core/
│   ├── crypto.ts          # @noble wrappers: DH, HKDF, HMAC, AEAD, Sign, Verify
│   ├── utils.ts           # base64, ArrayBuffer, TextEncoder/Decoder
│   └── types.ts           # KeyPair, PublicKey, PreKeyBundle, Ciphertext, etc.
├── x3dh/
│   ├── initiator.ts       # Alice: fetch bundle, compute DH1-4, derive SK, init ratchet
│   ├── responder.ts       # Bob: verify sig, compute DH1-4, derive SK, init ratchet
│   └── prekey-bundle.ts   # PreKeyBundle type + (de)serialization
├── ratchet/
│   ├── ratchet.ts         # Double Ratchet state machine (root/chain/message keys)
│   ├── chain.ts           # Sending/Receiving chains, KDF_CK (0x01/0x02 constants)
│   ├── header.ts          # Ratchet header (DH ratchet key, PN, N)
│   └── message.ts         # Encrypt/decrypt with message keys (AES-GCM-SIV)
├── sender-keys/           # Phase 2 — group messaging
│   ├── sender-key-state.ts
│   ├── sender-key-distribution.ts
│   └── group-cipher.ts
├── store/
│   ├── store-interface.ts  # The contract: identity, prekeys, sessions, sender keys
│   └── in-memory-store.ts  # In-memory implementation (for tests)
├── session/
│   ├── session-builder.ts  # Orchestrates X3DH → init ratchet
│   ├── session-cipher.ts   # Public encrypt/decrypt API
│   └── session-record.ts   # Session serialization, archived sessions
├── identity/
│   ├── identity-key.ts     # Ed25519 identity key pair + Montgomery conversion
│   └── key-helper.ts       # generateIdentityKeyPair, generatePreKeys, generateSignedPreKey
└── index.ts                # Public API: SignalProtocolManager facade
```

### Public API (facade)

```typescript
export class SignalProtocolManager {
  constructor(userId: string, store: SignalProtocolStore)

  async initialize(): Promise<void>
  // Generates identity key pair, signed prekey, batch of one-time prekeys
  // Uploads public parts to the key server

  async encryptMessage(remoteUserId: string, plaintext: string): Promise<Ciphertext>
  // Establishes session via X3DH if needed, then Double Ratchet encrypt

  async decryptMessage(remoteUserId: string, ciphertext: Ciphertext): Promise<string>
  // Decrypt via Double Ratchet, handle session establishment on first message
}
```

---

## 11. Implementation phases

### Phase 0 — Setup (1 day)

1. Backup current master: `git branch backup/master-original master`
2. Create migration branch: `git checkout -b feat/ts-signal-from-scratch`
3. Delete `public/libsignal-protocol.js` + remove `<script>` from `index.html`
4. Initialize TypeScript: `tsc --init`
5. Install: `@noble/curves @noble/hashes @noble/ciphers`
6. Create the directory structure from §10

### Phase 1 — Crypto core + X3DH + Double Ratchet (1-2 weeks)

1. `core/crypto.ts` — @noble wrappers (DH, HKDF, HMAC, AES-GCM-SIV, Ed25519)
2. `core/utils.ts` — base64, ArrayBuffer, TextEncoder
3. `core/types.ts` — type definitions
4. `identity/` — identity key pair (Ed25519 + Montgomery conversion), KeyHelper
5. `x3dh/` — initiator (DH1-4, F prefix, KDF), responder, prekey bundle
6. `ratchet/` — state machine, chains (0x01/0x02), header, message encrypt/decrypt
7. `session/` — session builder (X3DH → ratchet init), session cipher, session record
8. `store/` — store interface + in-memory implementation
9. `index.ts` — SignalProtocolManager facade
10. Backend: add `POST /keys/:userId` + `GET /keys/:userId` (atomic OPK consume)
11. Test: 2 browsers, 1:1 encrypted chat, verify forward secrecy

### Phase 2 — Sender Keys / groups (1 week)

1. `sender-keys/sender-key-state.ts` — chain key + signing key per sender per group
2. `sender-keys/sender-key-distribution.ts` — SKDM generation + processing
3. `sender-keys/group-cipher.ts` — group encrypt/decrypt
4. Backend: relay SKDMs + group ciphertexts
5. Test: 3 users, group chat, member departure (no history loss!)

### Phase 3 — Extract to own repo + integrate into up4it (1 week)

1. Extract `src/signal/` to `the-corner-inc/signal-protocol` repo
2. Set up npm package (package.json, build, publish)
3. In up4it: `npm install @up4it/signal-protocol`
4. Create Angular service wrapping the module
5. New DB tables: `signal_identity`, `signal_signed_prekey`, `signal_one_time_prekey`
6. New NestJS endpoints: prekey registration/fetch
7. Replace v1 crypto (`chat-crypto.service.ts`, `chat.service.ts` crypto parts)
8. Key backup: password-derived Argon2id
9. DB reset (no data migration needed)
10. Full test suite

### Phase 4 — Cleanup + publish (2-3 days)

1. Remove v1 code from up4it
2. Fix read-receipt bug (pre-existing, unrelated to crypto)
3. Publish `@up4it/signal-protocol` on npm
4. Write README with spec citations + usage examples
5. Security audit (external, before production)

---

## 12. References

### Primary (must read)

- **X3DH spec**: https://signal.org/docs/specifications/x3dh/
- **Double Ratchet spec**: https://signal.org/docs/specifications/doubleratchet/
- **Sesame spec**: https://signal.org/docs/specifications/sesame/ (future)
- **PQXDH spec**: https://signal.org/docs/specifications/pqxdh/ (future)

### Reference implementations (read for patterns, DO NOT copy)

- `@privacyresearch/libsignal-protocol-typescript` (GPL-3.0, stale but readable):
  https://github.com/privacyresearchgroup/libsignal-protocol-typescript
  - Has X3DH + Double Ratchet in TypeScript. Read `session-builder.ts` and
    `session-cipher.ts` for patterns. DO NOT copy code (GPL).
- `wireapp/proteus` (Rust, production at Wire):
  https://github.com/wireapp/proteus
  - Signal Protocol derivative in Rust. Read for Sender Keys patterns.
- `@getmaapp/signal-wasm` (AGPL-3.0, WASM build of libsignal):
  https://github.com/getmaapp/signal-wasm
  - Read for API design and store patterns. DO NOT copy code (AGPL).

### @noble documentation

- @noble/curves: https://github.com/paulmillr/noble-curves
- @noble/hashes: https://github.com/paulmillr/noble-hashes
- @noble/ciphers: https://github.com/paulmillr/noble-ciphers

### Academic

- "WhatsUpp with Sender Keys" (ASIACRYPT 2023) — formal analysis of group messaging
- "A Formal Analysis of the Signal Protocol" (Cohn-Gordon et al., 2016)

### Up4it v1 (reference for @noble usage patterns)

- `app/src/app/shared/services/chat-crypto.service.ts` — current @noble usage
  (X25519, AES-GCM, HKDF). Read for wrapper patterns. DO NOT copy (it's Angular-coupled).

---

## 13. Quick reference — constants and parameters

```typescript
// X3DH
const F = new Uint8Array(32).fill(0xff);  // domain separator, prepended to IKM
const X3DH_INFO = "Up4itX3DH_v1";
const X3DH_SALT = new Uint8Array(32);      // zero-filled (hash output length)

// Double Ratchet
const KDF_RK_INFO = "Up4itRatchet_v1";
const KDF_MK_INFO = "Up4itMessageKeys_v1";
const MESSAGE_KEY_SEED = 0x01;             // HMAC data for message key
const CHAIN_KEY_SEED = 0x02;               // HMAC data for next chain key
const MAX_SKIP = 1000;                     // max skipped message keys

// PreKeys
const DEFAULT_PREKEY_BATCH_SIZE = 100;     // one-time prekeys to generate
const SIGNED_PREKEY_ROTATION_DAYS = 7;     // rotate signed prekey weekly

// Key backup
const BACKUP_KDF = { m: 19456, t: 2, p: 1 };  // Argon2id params (~600ms)
const BACKUP_SALT_LENGTH = 16;
const BACKUP_NONCE_LENGTH = 12;
```
