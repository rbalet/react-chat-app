import { Router } from "express";
import { pool } from "../db.js";

export const usersRouter = Router();

/** GET /api/users/login/:userName — returns the user object (PoC: no password). */
usersRouter.get("/login/:userName", async (req, res) => {
  const { userName } = req.params;
  const { rows } = await pool.query(
    'SELECT id AS "_id", name, role, img, created_at FROM users WHERE name = $1',
    [userName],
  );
  if (rows.length === 0) {
    res.status(404).json({ error: "USER_NOT_FOUND" });
    return;
  }
  res.json({ data: rows[0] });
});

/** GET /api/users/:userid/:role — returns all users except the caller. */
usersRouter.get("/:userid/:role", async (req, res) => {
  const { userid, role } = req.params;
  const { rows } = await pool.query(
    'SELECT id AS "_id", name, role, img, created_at FROM users WHERE id != $1 ORDER BY name',
    [userid],
  );
  res.json({ data: rows });
});
