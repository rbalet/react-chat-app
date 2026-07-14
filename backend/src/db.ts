import pg from "pg";

const { Pool } = pg;

export const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ??
    "postgresql://postgres:postgres@localhost:5433/signal_poc",
});

// An idle client losing its connection (e.g. Postgres restart) emits 'error'
// on the pool; without a listener that is an uncaught exception → crash.
pool.on("error", (err) => {
  console.error("[db] idle client error:", err.message);
});

/**
 * Schema init. Tables are created IF NOT EXISTS — safe to call on every boot.
 * The PoC seeds 3 users (alice, bob, carol) on first run.
 *
 * Tables:
 * - users:           simple identity for the PoC (no auth, just names)
 * - prekey_bundle:   one row per user (identity key + signed prekey)
 * - one_time_prekey: pool of OPKs, composite PK (user_id, id) so different
 *   users can have OPKs with the same protocol-level id without conflict.
 *   Consumed atomically via ctid + FOR UPDATE SKIP LOCKED.
 */
export async function initDb(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      role        TEXT NOT NULL DEFAULT 'SOLO',
      img         TEXT,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS prekey_bundle (
      user_id         TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      registration_id INTEGER NOT NULL,
      identity_key    TEXT NOT NULL,
      spk_id          INTEGER NOT NULL,
      spk_public_key  TEXT NOT NULL,
      spk_signature   TEXT NOT NULL,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS one_time_prekey (
      user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      id         TEXT NOT NULL,
      public_key TEXT NOT NULL,
      PRIMARY KEY (user_id, id)
    );
    CREATE INDEX IF NOT EXISTS idx_otpk_user ON one_time_prekey (user_id);
  `);

  const { rows } = await pool.query("SELECT COUNT(*)::int AS c FROM users");
  if (rows[0].c === 0) {
    await pool.query(`
      INSERT INTO users (id, name, role, img) VALUES
        ('alice', 'Alice', 'SOLO', 'user1.png'),
        ('bob',   'Bob',   'SOLO', 'user2.png'),
        ('carol', 'Carol', 'SOLO', 'user3.png')
      ON CONFLICT DO NOTHING;
    `);
  }
}
