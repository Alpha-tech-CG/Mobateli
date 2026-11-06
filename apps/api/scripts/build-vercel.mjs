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

cpSync(join(repo, "packages", "db", "prisma", "schema.prisma"), join(out, "prisma", "schema.prisma"));

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
      scripts: { build: "prisma generate" },
      dependencies: deps,
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
      installCommand: "npm install",
      buildCommand: "npm run build",
      outputDirectory: "public",
      functions: {
        "api/index.js": {
          maxDuration: 30,
          includeFiles: engineBundled ? "{node_modules/pdfkit/js/data/**,bin/**}" : "node_modules/pdfkit/js/data/**",
        },
      },
      rewrites: [{ source: "/(.*)", destination: "/api" }],
    },
    null,
    2,
  ),
);

console.log(`Vercel bundle ready in ${out} — moteur Rust ${engineBundled ? "embarqué" : "ABSENT (règles regex seules)"}`);
