import fs from "node:fs";
import path from "node:path";
import express from "express";
import axios from "axios";

const app = express();
const UPLOADS = "/srv/uploads";

// ---- Path traversal ---------------------------------------------------------
app.get("/file", (req, res) => {
  res.send(fs.readFileSync("/srv/uploads/" + req.query.name)); // VULN: PATH
});

app.get("/download/:name", (req, res) => {
  const target = path.join(UPLOADS, req.params.name);
  fs.createReadStream(target).pipe(res); // VULN: PATH
});

app.get("/safe-file", (req, res) => {
  const target = path.resolve(UPLOADS, String(req.query.name));
  if (!target.startsWith(UPLOADS + path.sep)) return res.sendStatus(400);
  fs.createReadStream(target).pipe(res); // SAFE: PATH
});

export const banner = fs.readFileSync(path.join(__dirname, "banner.txt"), "utf8"); // SAFE: PATH

// ---- SSRF -------------------------------------------------------------------
app.get("/proxy", async (req, res) => {
  const r = await fetch(req.query.url as string); // VULN: SSRF
  res.send(await r.text());
});

app.post("/webhook-test", async (req, res) => {
  const target = req.body.callback;
  const r = await axios.post(target, { ok: true }); // VULN: SSRF
  res.json(r.data);
});

app.get("/weather", async (req, res) => {
  const city = encodeURIComponent(String(req.query.city));
  const r = await fetch(`https://api.weather.example.com/v1?q=${city}`); // SAFE: SSRF
  res.json(await r.json());
});

export async function health(): Promise<number> {
  const r = await fetch("https://status.example.com/health"); // SAFE: SSRF
  return r.status;
}

// ---- XSS --------------------------------------------------------------------
export function renderComment(el: HTMLElement, comment: string): void {
  el.innerHTML = comment; // VULN: XSS
}

export function renderGreeting(el: HTMLElement): void {
  const name = new URLSearchParams(location.search).get("name");
  document.write("<h1>Hello " + name + "</h1>"); // VULN: XSS
}

export function renderSafe(el: HTMLElement, comment: string): void {
  el.textContent = comment; // SAFE: XSS
}

export function clear(el: HTMLElement): void {
  el.innerHTML = ""; // SAFE: XSS
}

app.get("/hello", (req, res) => {
  res.send("<p>Hello " + req.query.name + "</p>"); // VULN: XSS
});

// ---- CORS -------------------------------------------------------------------
app.use((_req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*"); // VULN: CORS
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

export const corsOptions = { origin: ["https://app.example.com"], credentials: true }; // SAFE: CORS

export default app;
