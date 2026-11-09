// Assemble a self-contained Vercel deployment for the API in .vercel-deploy/.
//
// The monorepo's workspace packages (@codegate/db, @codegate/shared) are
// bundled into a single serverless function with esbuild; third-party
// packages stay external and are installed by Vercel with npm from a
// generated package.json (no pnpm workspace needed on Vercel's side).
import { build } from "esbuild";
import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const apiDir = join(here, "..");
const repo = join(apiDir, "..", "..");
const out = join(apiDir, ".vercel-deploy");

const readPkg = (p) => JSON.parse(readFileSync(join(p, "package.json"), "utf8"));
const apiPkg = readPkg(apiDir);
const dbPkg = readPkg(join(repo, "packages", "db"));
const sharedPkg = readPkg(join(repo, "packages", "shared"));

// Runtime dependencies = everything non-workspace the bundle imports.
const deps = {};
for (const pkg of [apiPkg.dependencies, dbPkg.dependencies, sharedPkg.dependencies]) {
  for (const [name, version] of Object.entries(pkg ?? {})) {
    if (!String(version).startsWith("workspace:")) deps[name] = version;
  }
}
deps.prisma = dbPkg.devDependencies.prisma; // needed for `prisma generate` on Vercel

rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, "api"), { recursive: true });
mkdirSync(join(out, "prisma"), { recursive: true });
mkdirSync(join(out, "public"), { recursive: true });

await build({
  entryPoints: [join(apiDir, "src", "vercel.ts")],
  outfile: join(out, "api", "index.js"),
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  external: Object.keys(deps),
  logLevel: "warning",
});

// Rust scan engine, loaded next to the bundle (new URL("./codegate_scan.wasm", import.meta.url)).
cpSync(join(apiDir, "src", "analysis", "engine", "codegate_scan.wasm"), join(out, "api", "codegate_scan.wasm"));
// Audit report branding, loaded next to the bundle (new URL("./assets/…", import.meta.url)).
cpSync(join(apiDir, "src", "lib", "assets"), join(out, "api", "assets"), { recursive: true });
cpSync(join(repo, "packages", "db", "prisma", "schema.prisma"), join(out, "prisma", "schema.prisma"));
// Migrations are applied by the Vercel build (see `scripts.build` below).
cpSync(join(repo, "packages", "db", "prisma", "migrations"), join(out, "prisma", "migrations"), { recursive: true });

// The Rust taint engine. Without it the deployed bot runs the regex rules
// only — far lower recall (0/5 of Juice Shop's SQL injections) and no
// corroboration. It must be a STATIC Linux x86_64 build (CI artifact
// `codegate-scan-linux-musl`): `CODEGATE_SCAN_LINUX_BIN=/path/to/codegate-scan`.
const engine = process.env.CODEGATE_SCAN_LINUX_BIN;
let engineBundled = false;
if (engine && existsSync(engine)) {
  mkdirSync(join(out, "bin"), { recursive: true });
  cpSync(engine, join(out, "bin", "codegate-scan"));
  chmodSync(join(out, "bin", "codegate-scan"), 0o755);
  engineBundled = true;
} else if (process.env.CODEGATE_ALLOW_NO_ENGINE !== "1") {
  console.error(
    "✖ Moteur Rust absent : définissez CODEGATE_SCAN_LINUX_BIN (artefact CI codegate-scan-linux-musl),\n" +
      "  ou CODEGATE_ALLOW_NO_ENGINE=1 pour déployer volontairement sans lui (règles regex seules).",
  );
  process.exit(1);
}
writeFileSync(join(out, "public", "robots.txt"), "User-agent: *\nDisallow: /\n");

writeFileSync(
  join(out, "package.json"),
  JSON.stringify(
    {
      name: "codegate-api",
      private: true,
      type: "module",
      engines: { node: "22.x" },
      // The build applies pending migrations BEFORE the new code goes live:
      // the production database URL is a sensitive variable only Vercel's
      // build/runtime can read. A failing migration fails the build, and the
      // previous deployment stays in production. Neon's pooled URL does not
      // suit migrations, hence the unpooled one when present.
      scripts: {
        // Production builds only: a preview must never migrate a database
        // that production may share.
        build:
          'if [ "$VERCEL_ENV" = "production" ]; then DATABASE_URL="${DATABASE_URL_UNPOOLED:-$DATABASE_URL}" prisma migrate deploy || exit 1; fi; prisma generate',
      },
      dependencies: deps,
      // Same security overrides as the monorepo (see pnpm-workspace.yaml).
      overrides: { zod: deps.zod },
    },
    null,
    2,
  ),
);

writeFileSync(
  join(out, "vercel.json"),
  JSON.stringify(
    {
      $schema: "https://openapi.vercel.sh/vercel.json",
      framework: null,
      // EU hosting (cahier §10.1), next to the Neon database (Frankfurt).
      regions: ["fra1"],
      installCommand: "npm install",
      buildCommand: "npm run build",
      outputDirectory: "public",
      functions: {
        "api/index.js": {
          // Whole-repository scans run after the response (waitUntil).
          maxDuration: 60,
          includeFiles: engineBundled
            ? "{node_modules/pdfkit/js/data/**,api/codegate_scan.wasm,api/assets/**,bin/**}"
            : "{node_modules/pdfkit/js/data/**,api/codegate_scan.wasm,api/assets/**}",
        },
      },
      rewrites: [{ source: "/(.*)", destination: "/api" }],
      // Daily maintenance: retention purge + proactive alerts (Hobby: daily).
      crons: [{ path: "/api/v1/cron/maintenance", schedule: "0 5 * * *" }],
    },
    null,
    2,
  ),
);

console.log(`Vercel bundle ready in ${out} — moteur Rust ${engineBundled ? "embarqué" : "ABSENT (règles regex seules)"}`);
