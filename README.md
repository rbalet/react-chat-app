# Secure Chat PoC — from-scratch Signal Protocol in TypeScript

> ⚠️ Prototype — Not for production use.

A React chat application whose end-to-end encryption is a **clean-room
TypeScript implementation of the Signal Protocol** — X3DH, Double Ratchet
and Sender Keys (groups) — living in [`src/signal/`](src/signal/README.md),
built exclusively on [`@noble`](https://paulmillr.com/noble/) crypto and
licensed **Apache-2.0**.

## Quick start

```bash
# One command: PostgreSQL + backend + frontend
pnpm run dev:all

# Or step by step:
cd backend && docker compose up -d                       # PostgreSQL 16 (port 5433)
cd backend && pnpm install && pnpm run dev               # API + WS on :4000
pnpm install && pnpm run dev                             # Vite, proxies /keys and /api to :4000
```

Vite serves on **:3000, or the next free port** (e.g. :3001 if another
app holds 3000 — watch the terminal output). Open two different browsers
and log in as `Alice` and `Bob` to chat.

## Scripts

| Command | What it does |
| ------- | ------------ |
| `pnpm run dev:all` | Start DB (Docker), backend API, and frontend in one terminal |
| `pnpm run test` | Run all 102 frontend tests (Vitest) |
| `cd backend && pnpm run test` | Run 13 backend tests (supertest, needs Docker) |
| `pnpm run smoke:group` | Smoke test: 4 users, group chat, encryption, rotation, departure/return (28 checks) |
| `pnpm run db:inspect` | Show prekey tables (who's registered, OPK counts) |
| `pnpm run db:verify` | Same as inspect, with descriptive labels |
| `pnpm run db:clean` | Wipe prekey bundles between test runs (fast, keeps users) |
| `pnpm run db:reset` | Full DB reset (destroy volume + recreate) |

## What the PoC demonstrates

- **1:1 end-to-end encryption**: sessions bootstrap asynchronously via
  **X3DH** (signed + one-time prekeys fetched from the server), then run
  the **Double Ratchet** — per-message **forward secrecy** (a compromised
  key never decrypts past messages) and **post-compromise security**
  (fresh DH entropy every round trip).
- **Group messaging** (module level, exercised by the test suite): **Sender
  Keys** with identity-signed distribution messages, per-message Ed25519
  signatures, key rotation that keeps in-flight messages decryptable, and
  skipped-key handling for out-of-order delivery.
- **Server holds no secrets**: it stores public prekey bundles (one-time
  prekeys consumed atomically under concurrency) and relays opaque
  ciphertext; plaintext never leaves the clients. Trust is TOFU — an
  identity key change is refused until the app clears the pin.
- **Robust transport**: the client auto-reconnects its WebSocket (1s→10s
  backoff) across backend restarts. Messages relayed while a peer is
  offline are dropped (no offline queue — PoC).

## Architecture

```
┌────────────── Browser A ─────────────┐        ┌───── Browser B ─────┐
│ React UI (2021 demo shell)           │        │        idem         │
│   └─ services/signal-gateway.ts      │        └─────────┬───────────┘
│       └─ src/signal/  ← the module   │                  │
│           SignalProtocolManager      │                  │
│           X3DH · Double Ratchet ·    │                  │
│           Sender Keys · stores       │                  │
└──────┬─────────────────────┬─────────┘                  │
       │ HTTP /keys, /api    │ WS /chat/:userId           │
       ▼                     ▼                            ▼
┌─────────────────────── backend/ (Express 5) ────────────────────────┐
│  prekey server ──► PostgreSQL 16       WS relay (stateless,         │
│  (atomic OPK consume)  (docker)        no message storage)          │
└─────────────────────────────────────────────────────────────────────┘
```

The module is framework-agnostic (zero React/DOM imports) and talks to
the outside world only through the injected `KeyServerClient` interface —
the same code runs in the browser UI and in headless Node test clients.

## Layout

| Path | What it is |
| ---- | ---------- |
| [`src/signal/`](src/signal/README.md) | The deliverable: framework-agnostic Signal Protocol module (X3DH, Double Ratchet, Sender Keys, stores, `SignalProtocolManager` facade). Apache-2.0. |
| [`backend/`](backend/README.md) | PoC backend: Express 5 + PostgreSQL prekey server (atomic one-time-prekey consumption) + stateless WebSocket relay. |
| `src/components/`, `src/services/` | Demo UI (React 17, 2021-era chat app) and its glue: `signal-gateway.ts` (legacy method names), `http-key-server.ts` (`KeyServerClient` over fetch). |

## Tests

```bash
pnpm run test        # frontend + protocol module (Vitest)
cd backend && pnpm run test   # supertest suite (needs the Postgres container)
```

The protocol suite covers RFC vectors (7748, 8032, 5869, 4648), protocol
correctness (out-of-order, replay, tampering, TOFU, forward secrecy,
concurrent-initiation tie-break, per-peer serialization) and group
messaging (rotation transition, skipped keys, SKDM forgery/TOFU). The
backend suite proves atomic OPK consumption under concurrency.

## Status

- ✅ Phase 0 — old GPL `libsignal-protocol.js` removed, TypeScript + Vite toolchain, versions pinned exact.
- ✅ Phase 1 — X3DH + Double Ratchet + sessions + stores + facade; backend prekey server; verified end-to-end across two isolated clients.
- ✅ Phase 2 — Sender Keys: identity-signed SKDMs, per-message signatures, multi-state rotation, skipped message keys.
- ✅ Audit — adversarial code review, edge case audit, full libsignal comparison. Critical fixes applied: identity binding, domain separators, rollback patterns, SKDM replay guard.
- ✅ Smoke test — 28 checks: 4 users, group chat, rotation, departure/return (0 failures).
- ✅ Module extracted to npm package `@up4it/signal-protocol` (Apache-2.0, 97 tests).

## Gaps deferred

| Gap | Why deferred |
| --- | ------------ |
| SPK rotation + OPK pool replenishment | PoC doesn't need long-lived keys |
| Archived sessions (multi-device) | Requires per-device session storage |
| Rate limiting + auth on prekey endpoints | PoC trusts all clients on localhost |
| Offline message queue | Messages dropped for offline users |
| React 17 UI (demo shell) | Only the signal module is production-ready |

## License & provenance

The protocol module (`src/signal/`) is **Apache-2.0**
([LICENSE](src/signal/LICENSE)) and a **clean-room implementation**: written
solely from the Signal specifications at <https://signal.org/docs/>, each of
which is placed in the public domain by its authors. No code was copied,
ported or translated from `libsignal` (AGPL-3.0) or any GPL implementation.
"Signal Protocol" is used descriptively; this project is not affiliated with
Signal Messenger LLC.

The UI shell descends from a 2021 demo chat app by QED42
([tutorial](https://www.youtube.com/watch?v=gNbdgIznjhU&ab_channel=QED42),
[blog](https://www.qed42.com/blog/developing-real-time-secure-chat-application-like-whatsapp-or-signal-with-end-end-encryption)),
originally paired with the archived `libsignal-protocol-javascript`. The
protocol implementation, backend and toolchain in this repo are new; the
old vendored library and its storage helpers are gone.
