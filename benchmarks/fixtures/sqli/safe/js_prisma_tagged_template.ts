// Fixture: Safe parameterized queries — JavaScript/TypeScript
// Expected: TRUE NEGATIVE (must NOT be flagged)
// Pattern: Prisma tagged template, Drizzle tagged template, pg parameterized, Knex bind

import { PrismaClient } from "@prisma/client";
import { drizzle } from "drizzle-orm/node-postgres";
import { sql } from "drizzle-orm";
import { Pool } from "pg";
import knex from "knex";
import express from "express";

const prisma = new PrismaClient();
const pool = new Pool();
const db = drizzle(process.env.DATABASE_URL!);
const app = express();

// SAFE: Prisma $queryRaw with tagged template — auto-parameterized
app.get("/user/:id", async (req, res) => {
  const userId = parseInt(req.params.id);
  // Tagged template: ${} processed by tag function, NOT JS string interpolation
  const user = await prisma.$queryRaw`
    SELECT * FROM "User" WHERE id = ${userId}
  `;
  res.json(user);
});

// SAFE: Prisma query builder — fully auto-parameterized
app.get("/users", async (req, res) => {
  const name = req.query.name as string;
  const users = await prisma.user.findMany({
    where: { name: { contains: name } },
  });
  res.json(users);
});

// SAFE: Drizzle sql tagged template — auto-parameterized
app.get("/posts/:id", async (req, res) => {
  const postId = parseInt(req.params.id);
  const post = await db.execute(
    sql`SELECT * FROM posts WHERE id = ${postId}`
  );
  res.json(post);
});

// SAFE: pg client with positional parameters
app.get("/products", async (req, res) => {
  const category = req.query.category as string;
  const result = await pool.query(
    "SELECT * FROM products WHERE category = $1",
    [category]
  );
  res.json(result.rows);
});

// SAFE: Knex with bind parameters
app.get("/orders", async (req, res) => {
  const db2 = knex({ client: "pg", connection: process.env.DATABASE_URL });
  const status = req.query.status as string;
  const orders = await db2.raw(
    "SELECT * FROM orders WHERE status = ?",
    [status]
  );
  res.json(orders);
});

// SAFE: Sequelize with replacements
import { Sequelize } from "sequelize";

const sequelize = new Sequelize("sqlite::memory:");

app.get("/items", async (req, res) => {
  const type = req.query.type as string;
  const items = await sequelize.query(
    "SELECT * FROM items WHERE type = ?",
    { replacements: [type] }
  );
  res.json(items);
});
