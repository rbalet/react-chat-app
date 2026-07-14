import "dotenv/config";
import http from "node:http";
import cors from "cors";
import express from "express";
import { initDb } from "./db.js";
import { keysRouter } from "./routes/keys.js";
import { usersRouter } from "./routes/users.js";
import { setupWebSocket } from "./ws.js";

async function main() {
  await initDb();
  console.log("[db] tables ready");

  const app = express();
  app.use(cors());
  app.use(express.json({ limit: "1mb" }));

  app.use("/api/users", usersRouter);
  app.use("/keys", keysRouter);

  app.get("/health", (_req, res) => res.json({ ok: true }));

  const port = Number(process.env.PORT) || 4000;
  const server = http.createServer(app);

  setupWebSocket(server);

  server.listen(port, () => {
    console.log(`[server] listening on http://localhost:${port}`);
    console.log(`[ws]      listening on ws://localhost:${port}/chat/:userId`);
  });
}

main().catch((err) => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});
