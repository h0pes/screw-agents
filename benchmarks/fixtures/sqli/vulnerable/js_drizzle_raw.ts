// Fixture: js-drizzle-raw — Drizzle ORM sql.raw() injection
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-89
// Pattern: sql.raw() in Drizzle ORM with interpolation
// Note: NO SAST tool (Semgrep, CodeQL) detects this pattern — Drizzle is too new

import { drizzle } from "drizzle-orm/node-postgres";
import { sql } from "drizzle-orm";
import { users } from "./schema";
import express from "express";

const db = drizzle(process.env.DATABASE_URL!);
const app = express();

// VULNERABLE: sql.raw() with template literal interpolation
app.get("/users/search", async (req, res) => {
  const name = req.query.name as string;
  // sql.raw() does NOT parameterize — raw string passed to DB
  const result = await db.execute(
    sql.raw(`SELECT * FROM users WHERE name = '${name}'`)
  );
  res.json(result);
});

// VULNERABLE: sql.raw() for ORDER BY with user input
app.get("/users", async (req, res) => {
  const sortField = req.query.sort as string;
  const result = await db
    .select()
    .from(users)
    .orderBy(sql.raw(sortField));
  res.json(result);
});

// VULNERABLE: Knex raw with template literal (for comparison)
import knex from "knex";

const db2 = knex({ client: "pg", connection: process.env.DATABASE_URL });

app.get("/posts", async (req, res) => {
  const category = req.query.category as string;
  const posts = await db2.raw(
    `SELECT * FROM posts WHERE category = '${category}'`
  );
  res.json(posts);
});
