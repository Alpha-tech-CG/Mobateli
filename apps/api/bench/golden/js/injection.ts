import express from "express";
import { exec, execFile, execSync } from "node:child_process";
import { db } from "./db";

const app = express();

// ---- SQL injection ----------------------------------------------------------
app.get("/users/:id", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE id = " + req.params.id); // VULN: SQLI
  res.json(rows);
});

app.get("/search", async (req, res) => {
  const name = req.query.name;
  const sql = `SELECT * FROM products WHERE name = '${name}'`;
  const rows = await db.query(sql); // VULN: SQLI
  res.json(rows);
});

app.get("/orders", async (req, res) => {
  const filter = req.query.status;
  const rows = await db.query( // ALSO: SQLI
    "SELECT * FROM orders WHERE status = '" + filter + "' ORDER BY id", // VULN: SQLI
  );
  res.json(rows);
});

app.get("/safe-user", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE id = $1", [req.query.id]); // SAFE: SQLI
  res.json(rows);
});

app.get("/safe-limit", async (req, res) => {
  const limit = parseInt(String(req.query.limit), 10);
  const rows = await db.query(`SELECT * FROM logs ORDER BY id LIMIT ${limit}`); // SAFE: SQLI
  res.json(rows);
});

const TABLE = "audit";
export const countSql = "SELECT count(*) FROM " + TABLE; // SAFE: SQLI

// ---- Command injection ------------------------------------------------------
app.post("/ping", (req, res) => {
  exec(`ping -c 1 ${req.body.host}`, (_e, out) => res.send(out)); // VULN: CMDI
});

app.post("/convert", (req, res) => {
  const file = req.body.file;
  const cmd = "convert " + file + " out.png";
  execSync(cmd); // VULN: CMDI
  res.sendStatus(204);
});

app.post("/safe-ping", (req, res) => {
  execFile("ping", ["-c", "1", String(req.body.host)], (_e, out) => res.send(out)); // SAFE: CMDI
});

export function buildInfo(): string {
  return execSync("git rev-parse HEAD").toString(); // SAFE: CMDI
}

// ---- Code injection ---------------------------------------------------------
app.post("/calc", (req, res) => {
  res.json({ result: eval(req.body.expr) }); // VULN: CODEI
});

app.post("/template", (req, res) => {
  const body = req.body.code;
  const fn = new Function("ctx", body); // VULN: CODEI
  res.json(fn({}));
});

export function retry(fn: () => void): void {
  setTimeout(fn, 1000);
}

export function parseConfig(raw: string): unknown {
  return JSON.parse(raw); // SAFE: CODEI
}

export const doc = "never call evaluate() on user input"; // SAFE: CODEI

export default app;
