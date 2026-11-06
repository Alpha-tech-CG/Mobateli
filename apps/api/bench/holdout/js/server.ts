import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import https from "node:https";
import crypto from "node:crypto";
import { exec, spawn } from "node:child_process";
import express from "express";
import cors from "cors";
import axios from "axios";
import got from "got";
import jwt from "jsonwebtoken";
import { knex, sequelize, prisma, escapeHtml } from "./deps";

const app = express();
const UPLOAD_DIR = "/var/app/uploads";
const BRANCH = "main";

// ---- SQL ---------------------------------------------------------------------
app.get("/items", async (req, res) => {
  const rows = await knex.raw(`SELECT * FROM items ORDER BY ${req.query.sort}`); // VULN: SQLI
  res.json(rows);
});

app.get("/accounts/:id", async (req, res) => {
  const id = req.params.id;
  const [rows] = await sequelize.query("SELECT * FROM accounts WHERE id = " + id); // VULN: SQLI
  res.json(rows);
});

app.post("/report", async (req, res) => {
  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM r WHERE k = '${req.body.k}'`); // VULN: SQLI
  res.json(rows);
});

app.get("/safe-items", async (req, res) => {
  const rows = await knex("items").where({ id: req.query.id }); // SAFE: SQLI
  res.json(rows);
});

app.get("/safe-accounts", async (req, res) => {
  const rows = await sequelize.query("SELECT * FROM accounts WHERE email = ?", { replacements: [req.query.email] }); // SAFE: SQLI
  res.json(rows);
});

// ---- Commands ----------------------------------------------------------------
app.post("/archive", (req, res) => {
  exec("tar -czf /tmp/out.tgz " + req.query.name, () => res.sendStatus(204)); // VULN: CMDI
});

app.get("/ls", (req, res) => {
  spawn("ls", ["-la", String(req.query.dir)]).stdout.pipe(res); // SAFE: CMDI
});

export function lastCommit(cb: (out: string) => void): void {
  exec(`git log -1 ${BRANCH}`, (_e, out) => cb(out)); // SAFE: CMDI
}

// ---- Code injection ----------------------------------------------------------
app.post("/sandbox", (req, res) => {
  res.json(vm.runInNewContext(req.body.code)); // VULN: CODEI
});

app.get("/later", (req, res) => {
  setTimeout(() => res.sendStatus(200), 10); // SAFE: CODEI
});

// ---- Files -------------------------------------------------------------------
app.get("/files/:name", (req, res) => {
  res.sendFile(req.params.name); // VULN: PATH
});

app.get("/logs", async (req, res) => {
  const data = await fs.promises.readFile(`${UPLOAD_DIR}/${req.query.f}`, "utf8"); // VULN: PATH
  res.type("text").send(data);
});

app.get("/safe-files", (req, res) => {
  fs.readFile(path.join(UPLOAD_DIR, path.basename(String(req.query.f))), (_e, d) => res.send(d)); // SAFE: PATH
});

// ---- Outbound requests -------------------------------------------------------
app.get("/preview", async (req, res) => {
  const { data } = await axios.get(req.query.target as string); // VULN: SSRF
  res.send(data);
});

app.post("/proxy", async (req, res) => {
  const body = await got(`${req.body.base}/api/health`).text(); // VULN: SSRF
  res.send(body);
});

app.get("/host", async (req, res) => {
  const r = await fetch(`https://${req.query.host}/status`); // VULN: SSRF
  res.json(await r.json());
});

app.get("/gh/:user", async (req, res) => {
  const r = await fetch(`https://api.github.com/users/${encodeURIComponent(req.params.user)}`); // SAFE: SSRF
  res.json(await r.json());
});

// ---- XSS ---------------------------------------------------------------------
app.get("/search", (req, res) => {
  res.send(`<div class="q">${req.query.q}</div>`); // VULN: XSS
});

app.post("/list", (req, res) => {
  const item = req.body.item;
  res.write("<li>" + item + "</li>"); // VULN: XSS
  res.end();
});

export function addBanner(el: HTMLElement, userHtml: string): void {
  el.insertAdjacentHTML("beforeend", userHtml); // VULN: XSS
}

app.get("/safe-search", (req, res) => {
  res.send(`<div class="q">${escapeHtml(String(req.query.q))}</div>`); // SAFE: XSS
});

app.get("/api/search", (req, res) => {
  res.json({ q: req.query.q }); // SAFE: XSS
});

// ---- Randomness / hashing / JWT / TLS / CORS --------------------------------
export function sendOtp(): number {
  const otp = Math.floor(100000 + Math.random() * 900000); // VULN: RANDOM
  return otp;
}

export function generateApiKey(): string {
  return Math.random().toString(16).slice(2); // VULN: RANDOM
}

export function shuffle<T>(xs: T[]): T[] {
  return xs.sort(() => Math.random() - 0.5); // SAFE: RANDOM
}

export function fingerprint(s: string): string {
  return crypto.createHash("MD5").update(s).digest("hex"); // VULN: HASH
}

export function checksum(s: string): string {
  return crypto.createHash("sha512").update(s).digest("hex"); // SAFE: HASH
}

app.get("/me", (req, res) => {
  const payload = jwt.decode(String(req.headers.authorization)); // VULN: JWT
  res.json(payload);
});

export function verify(token: string, secret: string): unknown {
  return jwt.verify(token, secret, { algorithms: ["HS256"] }); // SAFE: JWT
}

export const client = axios.create({ httpsAgent: new https.Agent({ rejectUnauthorized: false }) }); // VULN: TLS

app.use(cors({ origin: "*", credentials: true })); // VULN: CORS
app.use(cors({ origin: process.env.APP_URL, credentials: true })); // SAFE: CORS

export default app;
