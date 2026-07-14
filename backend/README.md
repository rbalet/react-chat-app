# signal-poc-backend

Minimal Express backend for the Signal Protocol PoC: PostgreSQL-backed
prekey server + stateless WebSocket relay.

## Run

```bash
docker compose up -d     # PostgreSQL 16 on :5433 (named volume pgdata)
pnpm install
pnpm run dev             # tsx watch, http://localhost:4000
```

The frontend (repo root, `pnpm run dev`) proxies `/keys` and `/api` to :4000;
the WebSocket connects directly to `ws://localhost:4000/chat/:userId`.

## Endpoints

| Method | Path                  | Behavior                                          |
| ------ | --------------------- | ------------------------------------------------- |
| POST   | `/keys/:userId`       | Upsert prekey bundle, replace all OPKs. 404 if the user does not exist, 400 on malformed bundle. |
| GET    | `/keys/:userId`       | Fetch bundle + **atomically consume one OPK** (`DELETE … ctid … FOR UPDATE SKIP LOCKED`). `oneTimePreKey` omitted when the pool is empty. 404 without bundle. |
| GET    | `/keys/count/:userId` | Remaining OPK count (for replenishment).          |
| GET    | `/api/users/login/:userName` | PoC login (no password), 404 unknown user. |
| GET    | `/api/users/:userid/:role`   | Contacts (everyone but the caller).        |
| GET    | `/health`             | Liveness.                                         |
| WS     | `/chat/:userId`       | Relay: forwards each message to sender + receiver connections. No storage — messages to offline users are dropped. |

## Schema

- `users` — seeded with alice / bob / carol on first boot.
- `prekey_bundle` — one row per user (identity key, signed prekey + signature).
- `one_time_prekey` — OPK pool, composite PK `(user_id, id)` so protocol-level
  prekey ids only need to be unique per user.

Tables are `CREATE TABLE IF NOT EXISTS` on boot; data lives in the
`pgdata` Docker volume and survives backend and container restarts.

## Tests

```bash
pnpm test     # 13 Vitest + supertest tests (needs the Postgres container)
```

Covers CRUD, upsert, validation, OPK exhaustion, 10-way concurrent OPK
consumption (all distinct — atomicity), and regression on the user routes.
Tests use dedicated `test-*` users, created and cascade-deleted by the
suite, so they never touch the seeded demo users' bundles.

## PoC limits (deliberate)

- No auth: anyone can publish keys for any userId. Real deployment must
  authenticate `POST /keys` (the frontend's TOFU only detects a key change).
- No offline message queue; the relay drops messages for closed sockets.
- CORS is wide open.
