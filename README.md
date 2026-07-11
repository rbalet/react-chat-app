# Secure Chat PoC — from-scratch Signal Protocol in TypeScript

A React chat application whose end-to-end encryption is a **clean-room
TypeScript implementation of the Signal Protocol** — X3DH, Double Ratchet
and Sender Keys (groups) — living in [`src/signal/`](src/signal/README.md),
built exclusively on [`@noble`](https://paulmillr.com/noble/) crypto and
licensed **Apache-2.0**. No code from `libsignal` (AGPL/GPL) is used.

**[BRIEF.md](BRIEF.md)** is the project's source of truth (context, legal
constraints, design, phase plan). The protocol module is developed here
(Phases 0–2, done) and will be extracted to its own npm package
(`@up4it/signal-protocol`, Phase 3).

## Quick start (3 processes, pnpm)

```bash
# 1. PostgreSQL 16 (port 5433)
cd backend && docker compose up -d

# 2. Prekey server + WS relay on :4000
cd backend && pnpm install && pnpm run dev

# 3. Frontend (Vite, proxies /keys and /api to :4000)
pnpm install && pnpm run dev
```

Open two different browsers (or two tabs — the in-memory signal store is
per-tab), log in as `Alice` and `Bob`, and chat. Prekeys live in
PostgreSQL ([backend/README.md](backend/README.md)); messages transit
encrypted through the WS relay and are never stored server-side. The
client auto-reconnects its WebSocket (1s→10s backoff) when the backend
restarts; messages relayed while a peer is disconnected are dropped
(no offline queue — PoC).

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
- ⬜ Phase 3 — extraction to its own repo / npm publish, SPK rotation + OPK replenishment, Sesame (multi-device).

## Provenance

The UI shell descends from a 2021 demo chat app by QED42
([tutorial](https://www.youtube.com/watch?v=gNbdgIznjhU&ab_channel=QED42),
[blog](https://www.qed42.com/blog/developing-real-time-secure-chat-application-like-whatsapp-or-signal-with-end-end-encryption)),
originally paired with the archived `libsignal-protocol-javascript`. The
protocol implementation, backend and toolchain in this repo are new; the
old vendored library and its storage helpers are gone.
