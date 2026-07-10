import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import http from "node:http";
import express from "express";
import cors from "cors";
import request from "supertest";
import { pool, initDb } from "../db.js";
import { keysRouter } from "../routes/keys.js";
import { usersRouter } from "../routes/users.js";

let app: express.Express;

beforeAll(async () => {
  await initDb();
  app = express();
  app.use(cors());
  app.use(express.json());
  app.use("/api/users", usersRouter);
  app.use("/keys", keysRouter);
});

afterAll(async () => {
  await pool.end();
});

/** Clean prekey data before each group so tests are isolated. */
async function cleanPrekeys(userIds: string[]): Promise<void> {
  for (const id of userIds) {
    await pool.query("DELETE FROM one_time_prekey WHERE user_id = $1", [id]);
    await pool.query("DELETE FROM prekey_bundle WHERE user_id = $1", [id]);
  }
}

const MOCK_BUNDLE = {
  registrationId: 12345,
  identityKey: "dGVzdC1pZGVudGl0eS1rZXk=",
  signedPreKey: {
    id: 1,
    publicKey: "dGVzdC1zcGstdGVzdA==",
    signature: "dGVzdC1zaWduYXR1cmU=",
  },
  oneTimePreKeys: Array.from({ length: 5 }, (_, i) => ({
    id: 100 + i,
    publicKey: `b3BrLXRlc3Qt${i}`,
  })),
};

describe("POST /keys/:userId", () => {
  beforeEach(async () => {
    await cleanPrekeys(["alice"]);
  });

  it("stores a prekey bundle + OPKs", async () => {
    const res = await request(app).post(`/keys/alice`).send(MOCK_BUNDLE);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.count).toBe(5);
  });

  it("replaces the bundle on re-upload (upsert)", async () => {
    const newBundle = {
      ...MOCK_BUNDLE,
      registrationId: 99999,
      oneTimePreKeys: [{ id: 200, publicKey: "bmV3LW9waw==" }],
    };

    const res = await request(app).post(`/keys/alice`).send(newBundle);
    expect(res.status).toBe(200);
    expect(res.body.count).toBe(1);

    const fetchRes = await request(app).get(`/keys/alice`);
    expect(fetchRes.body.registrationId).toBe(99999);
  });

  it("rejects an invalid bundle", async () => {
    const res = await request(app).post(`/keys/alice`).send({ registrationId: 1 });
    expect(res.status).toBe(400);
  });
});

describe("GET /keys/:userId", () => {
  beforeEach(async () => {
    await cleanPrekeys(["bob", "carol", "alice"]);
  });

  it("returns the bundle and consumes one OPK", async () => {
    await request(app).post(`/keys/bob`).send({
      ...MOCK_BUNDLE,
      oneTimePreKeys: [
        { id: 1, publicKey: "b3BrLTE=" },
        { id: 2, publicKey: "b3BrLTI=" },
        { id: 3, publicKey: "b3BrLTM=" },
      ],
    });

    const res = await request(app).get(`/keys/bob`);
    expect(res.status).toBe(200);
    expect(res.body.identityKey).toBeDefined();
    expect(res.body.signedPreKey.publicKey).toBeDefined();
    expect(res.body.oneTimePreKey).toBeDefined();
    expect(res.body.oneTimePreKey.publicKey).toMatch(/^b3Br/);
  });

  it("returns 404 for an unknown user", async () => {
    const res = await request(app).get(`/keys/ghost`);
    expect(res.status).toBe(404);
  });

  it("omits oneTimePreKey when the pool is exhausted", async () => {
    await request(app).post(`/keys/carol`).send({
      ...MOCK_BUNDLE,
      oneTimePreKeys: [{ id: 42, publicKey: "b25seS1vbmU=" }],
    });

    const r1 = await request(app).get(`/keys/carol`);
    expect(r1.body.oneTimePreKey).toBeDefined();

    const r2 = await request(app).get(`/keys/carol`);
    expect(r2.body.oneTimePreKey).toBeUndefined();
  });

  it("atomically consumes different OPKs on concurrent requests", async () => {
    await request(app).post(`/keys/alice`).send({
      ...MOCK_BUNDLE,
      oneTimePreKeys: Array.from({ length: 10 }, (_, i) => ({
        id: 500 + i,
        publicKey: `Y29uY3VyLTEt${i}`,
      })),
    });

    // Fire 10 concurrent requests — each must get a DISTINCT OPK
    const results = await Promise.all(
      Array.from({ length: 10 }, () => request(app).get(`/keys/alice`)),
    );

    const opkIds = results
      .map((r) => r.body.oneTimePreKey?.id)
      .filter((id): id is number => id !== undefined);

    expect(opkIds).toHaveLength(10);
    expect(new Set(opkIds).size).toBe(10); // all distinct — atomicity proven

    // Pool should now be empty
    const countRes = await request(app).get(`/keys/count/alice`);
    expect(countRes.body.count).toBe(0);
  });
});

describe("GET /keys/count/:userId", () => {
  beforeEach(async () => {
    await cleanPrekeys(["alice"]);
  });

  it("returns the remaining OPK count", async () => {
    await request(app).post(`/keys/alice`).send({
      ...MOCK_BUNDLE,
      oneTimePreKeys: [
        { id: 1, publicKey: "YQ==" },
        { id: 2, publicKey: "Yg==" },
        { id: 3, publicKey: "Yw==" },
      ],
    });

    const res = await request(app).get(`/keys/count/alice`);
    expect(res.status).toBe(200);
    expect(res.body.count).toBe(3);
  });
});

describe("Regression — existing user endpoints", () => {
  it("login returns a seeded user", async () => {
    const res = await request(app).get(`/api/users/login/Alice`);
    expect(res.status).toBe(200);
    expect(res.body.data.name).toBe("Alice");
  });

  it("contacts returns other users", async () => {
    const res = await request(app).get(`/api/users/alice/SOLO`);
    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
    expect(res.body.data.every((u: { _id: string }) => u._id !== "alice")).toBe(true);
  });
});
