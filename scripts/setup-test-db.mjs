// Recreate the integration-test database and apply all migrations.
//
// The Prisma schema engine is unreliable over Docker Desktop's NAT on this
// setup, so we apply migrations deterministically through the container's psql
// (inside Docker's network). Requires the codegate-postgres container.
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const CONTAINER = "codegate-postgres";
const TEST_DB = "codegate_test";
const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "packages", "db", "prisma", "migrations");

function psql(db, sql) {
  execFileSync("docker", ["exec", "-i", CONTAINER, "psql", "-U", "codegate", "-d", db, "-v", "ON_ERROR_STOP=1"], {
    input: sql,
    stdio: ["pipe", "ignore", "inherit"],
  });
}

console.log(`Recreating ${TEST_DB}…`);
psql("postgres", `DROP DATABASE IF EXISTS ${TEST_DB} WITH (FORCE); CREATE DATABASE ${TEST_DB};`);

const migrations = readdirSync(migrationsDir, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

for (const m of migrations) {
  const sql = readFileSync(join(migrationsDir, m, "migration.sql"), "utf8");
  process.stdout.write(`  applying ${m}… `);
  psql(TEST_DB, sql);
  console.log("ok");
}

console.log(`${TEST_DB} ready (${migrations.length} migrations).`);
