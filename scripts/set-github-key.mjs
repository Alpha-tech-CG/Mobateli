// Put a GitHub App private key (.pem) into .env as GITHUB_APP_PRIVATE_KEY,
// on one line ("\n" escapes, unescaped by the API config). The key is never
// printed. Replaces an existing GITHUB_APP_PRIVATE_KEY line.
//
// Usage (from the repository root):
//   node scripts/set-github-key.mjs "C:\Users\me\Downloads\my-app.private-key.pem"
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const pemPath = process.argv[2];
const envPath = resolve(process.argv[3] ?? ".env");

if (!pemPath) {
  console.error('Usage: node scripts/set-github-key.mjs "<chemin du fichier .pem>" [.env]');
  process.exit(1);
}
const pem = readFileSync(pemPath, "utf8").trim();
if (!/^-----BEGIN (RSA )?PRIVATE KEY-----[\s\S]+-----END (RSA )?PRIVATE KEY-----$/.test(pem)) {
  console.error("Ce fichier ne ressemble pas à une clé privée PEM de GitHub App.");
  process.exit(1);
}
if (!existsSync(envPath)) {
  console.error(`Fichier introuvable : ${envPath}`);
  process.exit(1);
}

const line = `GITHUB_APP_PRIVATE_KEY=${pem.replace(/\r?\n/g, "\\n")}`;
const env = readFileSync(envPath, "utf8");
const next = /^GITHUB_APP_PRIVATE_KEY=.*$/m.test(env)
  ? env.replace(/^GITHUB_APP_PRIVATE_KEY=.*$/m, () => line)
  : `${env.replace(/\s*$/, "")}\n${line}\n`;
writeFileSync(envPath, next);
console.log(`GITHUB_APP_PRIVATE_KEY écrite dans ${envPath} (valeur non affichée).`);
