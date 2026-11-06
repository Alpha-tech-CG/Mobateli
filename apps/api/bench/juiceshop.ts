/**
 * External benchmark: run CodeGate over OWASP Juice Shop's source and compare
 * with the project's own ground truth — the `// vuln-code-snippet vuln-line
 * <challengeKey>` annotations its maintainers put on vulnerable lines.
 *
 *   git clone --depth 1 https://github.com/juice-shop/juice-shop.git /tmp/js
 *   pnpm --filter @codegate/api exec node --import tsx bench/juiceshop.ts /tmp/js [--rust] [--json out.json]
 *
 * Nothing in the clone is executed; files are only read. The annotation
 * comments are stripped before analysis so they cannot influence a rule.
 * Not part of CI (needs the network); run it by hand when the engines change.
 * Works on any checkout (JS/TS/Python): without annotations it simply lists
 * every alert for manual triage (used for NodeGoat and PyGoat too).
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeDiff, analyzeDiffWithIntel } from "../src/analysis/analyzer.js";
import { IGNORE_FILE, parseIgnoreFile } from "../src/analysis/ignore.js";
import { alertsFrom, type Alert } from "./run.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "../../..");

/**
 * Juice Shop challenge → CodeGate category, or null when the weakness is
 * outside what CodeGate looks for (access control, business logic, NoSQL,
 * open redirect, LLM prompt injection…). Unknown keys are reported as such.
 */
const CHALLENGE_CATEGORY: Record<string, string | null> = {
  loginAdminChallenge: "SQLI",
  loginBenderChallenge: "SQLI",
  loginJimChallenge: "SQLI",
  unionSqlInjectionChallenge: "SQLI",
  dbSchemaChallenge: "SQLI",
  localXssChallenge: "XSS",
  xssBonusChallenge: "XSS",
  restfulXssChallenge: "XSS",
  noSqlReviewsChallenge: "NOSQL",
  forgedReviewChallenge: null,
  // The flaw is the allowlist check (`url.includes(allowed)`), not a missing
  // one: a taint rule sees a guarded redirect. Scored anyway, to be honest.
  redirectChallenge: "REDIRECT",
  redirectCryptoCurrencyChallenge: null,
  directoryListingChallenge: null,
  accessLogDisclosureChallenge: null,
  exposedMetricsChallenge: null,
  adminSectionChallenge: null,
  scoreBoardChallenge: null,
  web3SandboxChallenge: null,
  tokenSaleChallenge: null,
  changeProductChallenge: null,
  registerAdminChallenge: null,
  resetPasswordMortyChallenge: null,
  weakPasswordChallenge: null,
  chatbotPromptInjectionChallenge: null,
  chatbotGreedyInjectionChallenge: null,
};

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "codefixes", "test", "tests", "cypress", "coverage", "migrations", "venv", ".venv"]);
const ANNOTATION = /\s*\/\/\s*vuln-code-snippet\b.*$/;

const isSource = (name: string) =>
  /\.(ts|tsx|js|jsx|mjs|cjs|py)$/.test(name) && !/\.(spec|test|d)\.ts$/.test(name) && !/^test_.*\.py$/.test(name);

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return SKIP_DIRS.has(name) ? [] : walk(full);
    return isSource(name) ? [full] : [];
  });
}

/**
 * Files a pull request can actually contain: in a git checkout, the tracked
 * files (so build output, caches and local-only folders — `.next`, `.turbo`,
 * `.pnpm-store`… — are left out, as they are of every PR); otherwise a walk.
 */
function sourceFiles(root: string): string[] {
  if (!existsSync(join(root, ".git"))) return walk(root);
  const tracked = execFileSync("git", ["-C", root, "ls-files", "-z"], { encoding: "utf8", maxBuffer: 1 << 28 })
    .split("\0")
    .filter(Boolean);
  // An empty index (a checkout that failed, e.g. on Windows long paths): walk.
  if (tracked.length === 0) return walk(root);
  return tracked
    .filter((p) => !p.split("/").some((seg) => SKIP_DIRS.has(seg)))
    .filter((p) => isSource(p.split("/").pop()!))
    .map((p) => join(root, p))
    .filter((full) => existsSync(full));
}

interface VulnLine {
  file: string;
  line: number;
  challenges: string[];
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const jsonAt = args.indexOf("--json");
  const root = args.find((a, i) => !a.startsWith("--") && (jsonAt === -1 || i !== jsonAt + 1));
  if (!root) throw new Error("usage: juiceshop.ts <juice-shop checkout> [--rust] [--json out.json]");
  const useRust = args.includes("--rust");
  const jsonOut = jsonAt === -1 ? undefined : args[jsonAt + 1];

  const vulnLines: VulnLine[] = [];
  const parts: string[] = [];
  let totalLines = 0;
  // The repository's own exclusions, as the bot applies them.
  const ignoreAt = join(root, IGNORE_FILE);
  const isIgnored = existsSync(ignoreAt) ? parseIgnoreFile(readFileSync(ignoreAt, "utf8")) : () => false;
  const files = sourceFiles(root).filter((f) => !isIgnored(relative(root, f).split("\\").join("/")));
  for (const full of files) {
    const path = relative(root, full).split("\\").join("/");
    const lines = readFileSync(full, "utf8").replace(/\r\n/g, "\n").split("\n");
    totalLines += lines.length;
    const clean = lines.map((l, i) => {
      const m = l.match(/vuln-code-snippet vuln-line ([\w ]+)/);
      if (m) vulnLines.push({ file: path, line: i + 1, challenges: m[1]!.trim().split(/\s+/) });
      return l.replace(ANNOTATION, "");
    });
    parts.push(
      [`diff --git a/${path} b/${path}`, "--- /dev/null", `+++ b/${path}`, `@@ -0,0 +1,${clean.length} @@`, ...clean.map((l) => `+${l}`)].join("\n"),
    );
  }
  const diff = parts.join("\n");

  const exe = process.platform === "win32" ? "codegate-scan.exe" : "codegate-scan";
  const analyze = (d: string) =>
    useRust
      ? analyzeDiffWithIntel(d, {
          fetchImpl: () => Promise.reject(new Error("offline")),
          semgrep: { runner: async () => "{}" },
          rust: {
            binaryPath: process.env.CODEGATE_SCAN_BIN ?? join(REPO, "services/scan-engine/target/release", exe),
            timeoutMs: 120_000,
          },
        })
      : Promise.resolve(analyzeDiff(d));
  const t0 = Date.now();
  const result = await analyze(diff);
  const ms = Date.now() - t0;
  const alerts = alertsFrom(result).filter((a) => a.category !== "CONFIG");

  console.log(`# Juice Shop — moteurs : ${useRust ? "core,rust" : "core"}`);
  console.log(`${files.length} fichiers, ${totalLines} lignes, ${alerts.length} alertes, ${ms} ms`);
  console.log(`Tout le dépôt comme une seule PR : score ${result.riskScore}, décision ${result.decision} (${result.status})`);

  // One PR per file — how the bot actually judges: how many would be
  // warned or blocked, and what drives each verdict.
  if (args.includes("--per-file")) {
    const verdicts = new Map<string, string[]>();
    for (const part of parts) {
      const r = await analyze(part);
      const file = /^\+\+\+ b\/(.+)$/m.exec(part)?.[1] ?? "?";
      verdicts.set(r.status, [...(verdicts.get(r.status) ?? []), `${file} (score ${r.riskScore})`]);
    }
    console.log("Une PR par fichier :");
    for (const [status, list] of verdicts) {
      console.log(`  ${status.padEnd(9)} ${list.length}`);
      if (status !== "passed") for (const f of list) console.log(`      ${f}`);
    }
  }
  console.log("");

  // ---- Ground truth: annotated vulnerable lines --------------------------------
  const byChallenge = new Map<string, VulnLine[]>();
  for (const v of vulnLines) for (const c of v.challenges) byChallenge.set(c, [...(byChallenge.get(c) ?? []), v]);
  const at = (v: VulnLine) => alerts.filter((a) => a.file === v.file && a.line === v.line);

  let inScope = 0;
  let detected = 0;
  console.log("défi                              catégorie   détecté   alertes sur la ligne");
  for (const [challenge, lines] of [...byChallenge].sort()) {
    const cat = challenge in CHALLENGE_CATEGORY ? CHALLENGE_CATEGORY[challenge] : undefined;
    const hits = lines.flatMap(at);
    const ok = cat ? hits.some((h) => h.category === cat) : false;
    if (cat) {
      inScope++;
      if (ok) detected++;
    }
    const label = cat === undefined ? "inconnu" : cat === null ? "hors champ" : cat;
    console.log(
      `${challenge.padEnd(34)}${label.padEnd(12)}${(cat ? (ok ? "oui" : "NON") : "—").padEnd(10)}${hits.map((h) => `${h.category}:${h.source}`).join(", ")}`,
    );
  }
  console.log(`\nDéfis dans le périmètre de CodeGate détectés : ${detected}/${inScope} (${byChallenge.size} défis annotés au total)\n`);

  // ---- Everything else CodeGate reports, for manual triage ---------------------
  const byRule = new Map<string, Alert[]>();
  for (const a of alerts) byRule.set(`${a.category} ${a.source}`, [...(byRule.get(`${a.category} ${a.source}`) ?? []), a]);
  console.log("Toutes les alertes, par règle :");
  for (const [rule, list] of [...byRule].sort((x, y) => y[1].length - x[1].length)) {
    console.log(`  ${String(list.length).padStart(4)}  ${rule}`);
  }
  if (jsonOut) writeFileSync(jsonOut, JSON.stringify({ alerts, vulnLines }, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
