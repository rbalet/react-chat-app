import { Router } from "express";
import { pool } from "../db.js";

export const keysRouter = Router();

/**
 * POST /keys/:userId
 * Upload (or replace) the prekey bundle for a user.
 * Body: PublishedKeys { registrationId, identityKey, signedPreKey, oneTimePreKeys[] }
 */
keysRouter.post("/:userId", async (req, res) => {
  const { userId } = req.params;
  const { registrationId, identityKey, signedPreKey, oneTimePreKeys } = req.body;

  if (
    !registrationId ||
    !identityKey ||
    !signedPreKey?.publicKey ||
    !signedPreKey?.signature ||
    !Array.isArray(oneTimePreKeys)
  ) {
    res.status(400).json({ error: "INVALID_BUNDLE" });
    return;
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    await client.query(
      `INSERT INTO prekey_bundle (user_id, registration_id, identity_key, spk_id, spk_public_key, spk_signature)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (user_id) DO UPDATE SET
         registration_id = EXCLUDED.registration_id,
         identity_key    = EXCLUDED.identity_key,
         spk_id          = EXCLUDED.spk_id,
         spk_public_key  = EXCLUDED.spk_public_key,
         spk_signature   = EXCLUDED.spk_signature,
         created_at      = now()`,
      [
        userId,
        registrationId,
        identityKey,
        signedPreKey.id,
        signedPreKey.publicKey,
        signedPreKey.signature,
      ],
    );

    await client.query("DELETE FROM one_time_prekey WHERE user_id = $1", [userId]);

    for (const opk of oneTimePreKeys) {
      await client.query(
        "INSERT INTO one_time_prekey (user_id, id, public_key) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        [userId, String(opk.id), opk.publicKey],
      );
    }

    await client.query("COMMIT");
    res.json({ ok: true, count: oneTimePreKeys.length });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("publishKeys error:", err);
    res.status(500).json({ error: "INTERNAL" });
  } finally {
    client.release();
  }
});

/**
 * GET /keys/:userId
 * Fetch the prekey bundle and atomically consume one one-time prekey.
 * The DELETE ... FOR UPDATE SKIP LOCKED pattern guarantees that two
 * concurrent requests never receive the same OPK (X3DH §3.3).
 */
keysRouter.get("/:userId", async (req, res) => {
  const { userId } = req.params;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const bundleResult = await client.query(
      `SELECT registration_id, identity_key, spk_id, spk_public_key, spk_signature
       FROM prekey_bundle WHERE user_id = $1`,
      [userId],
    );

    if (bundleResult.rows.length === 0) {
      await client.query("ROLLBACK");
      res.status(404).json({ error: "NO_BUNDLE" });
      return;
    }

    const b = bundleResult.rows[0];

    // Atomic consume: ctid guarantees exactly one row is deleted even with
    // a composite PK (user_id, id). FOR UPDATE SKIP LOCKED prevents two
    // concurrent requests from grabbing the same OPK (X3DH §3.3).
    const opkResult = await client.query(
      `DELETE FROM one_time_prekey
       WHERE ctid IN (
         SELECT ctid FROM one_time_prekey
         WHERE user_id = $1
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       RETURNING id, public_key`,
      [userId],
    );

    await client.query("COMMIT");

    const oneTimePreKey =
      opkResult.rows.length > 0
        ? { id: Number(opkResult.rows[0].id), publicKey: opkResult.rows[0].public_key }
        : undefined;

    res.json({
      registrationId: b.registration_id,
      identityKey: b.identity_key,
      signedPreKey: {
        id: b.spk_id,
        publicKey: b.spk_public_key,
        signature: b.spk_signature,
      },
      ...(oneTimePreKey && { oneTimePreKey }),
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("fetchPreKeyBundle error:", err);
    res.status(500).json({ error: "INTERNAL" });
  } finally {
    client.release();
  }
});

/**
 * GET /keys/count/:userId
 * How many one-time prekeys remain for this user.
 */
keysRouter.get("/count/:userId", async (req, res) => {
  const { userId } = req.params;
  const { rows } = await pool.query(
    "SELECT COUNT(*)::int AS count FROM one_time_prekey WHERE user_id = $1",
    [userId],
  );
  res.json({ count: rows[0].count });
});
