// Fixture: js-prisma-rawunsafe + js-prisma-raw-bypass — Prisma injection vectors
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-89
// Pattern: $queryRawUnsafe with template literal, Prisma.raw() bypass
// Note: NO SAST tool (Semgrep, CodeQL) detects these patterns

import { PrismaClient, Prisma } from "@prisma/client";
import express from "express";

const prisma = new PrismaClient();
const app = express();

// VULNERABLE: $queryRawUnsafe with template literal interpolation
app.get("/user/:id", async (req, res) => {
  const userId = req.params.id;
  // $queryRawUnsafe does NOT parameterize — template literal is raw string concat
  const user = await prisma.$queryRawUnsafe(
    `SELECT * FROM "User" WHERE id = ${userId}`
  );
  res.json(user);
});

// VULNERABLE: Prisma.raw() bypasses safe tagged template API
app.get("/users", async (req, res) => {
  const sortCol = req.query.sort as string;
  // Prisma.raw() explicitly opts out of parameterization
  const users = await prisma.$queryRaw`
    SELECT * FROM "User" ORDER BY ${Prisma.raw(sortCol)}
  `;
  res.json(users);
});

// VULNERABLE: $executeRawUnsafe with string concatenation
app.delete("/user/:id", async (req, res) => {
  const userId = req.params.id;
  await prisma.$executeRawUnsafe(
    "DELETE FROM \"User\" WHERE id = " + userId
  );
  res.json({ deleted: true });
});

// VULNERABLE: Sequelize.literal with user input
import { Sequelize, DataTypes } from "sequelize";

const sequelize = new Sequelize("sqlite::memory:");

app.get("/posts", async (req, res) => {
  const sort = req.query.sort as string;
  const posts = await sequelize.models.Post.findAll({
    order: Sequelize.literal(sort),
  });
  res.json(posts);
});
