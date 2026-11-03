// Assemble a self-contained Vercel deployment for the API in .vercel-deploy/.
//
// The monorepo's workspace packages (@codegate/db, @codegate/shared) are
// bundled into a single serverless function with esbuild; third-party
// packages stay external and are installed by Vercel with npm from a
// generated package.json (no pnpm workspace needed on Vercel's side).
import { build } from "esbuild";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
cpSync(join(repo, "packages", "db", "prisma", "schema.prisma"), join(out, "prisma", "schema.prisma"));
cpSync(join(repo, "packages", "db", "prisma", "migrations"), join(out, "prisma", "migrations"), {
  recursive: true,
});
writeFileSync(join(out, "public", "robots.txt"), "User-agent: *\nDisallow: /\n");

writeFileSync(
  join(out, "package.json"),
  JSON.stringify(
    {
      name: "codegate-api",
      private: true,
      type: "module",
      engines: { node: "22.x" },
      // Sensitive Neon vars can't be pulled locally, so migrations run here,
      // on Vercel, against the direct (non-PgBouncer) endpoint.
      scripts: {
        build:
          'DATABASE_URL="${DATABASE_URL_UNPOOLED:-$DATABASE_URL}" prisma migrate deploy && prisma generate',
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
          includeFiles: "{node_modules/pdfkit/js/data/**,api/codegate_scan.wasm}",
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

console.log(`Vercel bundle ready in ${out}`);
