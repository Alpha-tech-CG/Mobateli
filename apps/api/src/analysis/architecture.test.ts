import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeArchitecture, isArchitectureSource } from "./architecture.js";
import type { FindingResult } from "./types.js";

const f = (path: string, content: string) => ({ path, content });

/** A small layered app: route → service → db, plus config. */
const layered = [
  f("package.json", JSON.stringify({ name: "demo" })),
  f("src/server.ts", `import { users } from "./routes/users.js";\nimport { orders } from "./routes/orders.js";\napp.listen(3000);`),
  f("src/routes/users.ts", `import { listUsers } from "../services/users.js";\nrouter.get("/users", listUsers);`),
  f("src/routes/orders.ts", `import { listOrders } from "../services/orders";\nrouter.get("/orders", listOrders);`),
  f("src/services/users.ts", `import { db } from "../db/client";\nexport const listUsers = (q) => db.query("SELECT * FROM users WHERE name = '" + q + "'");`),
  f("src/services/orders.ts", `import { db } from "../db/client";\nexport const listOrders = () => db.all();`),
  f("src/db/client.ts", `import { config } from "../config";\nexport const db = connect(config.url);`),
  f("src/config.ts", `export const config = { url: process.env.DB_URL, a: process.env.A, b: process.env.B };`),
  f("src/services/users.test.ts", `import { listUsers } from "./users";`),
];

const sqli: FindingResult = {
  type: "sast",
  severity: "high",
  title: "Requête SQL construite par concaténation",
  description: "",
  filePath: "src/services/users.ts",
  line: 2,
};

test("only source files take part (no tests, declarations, assets)", () => {
  assert.equal(isArchitectureSource("src/a.ts"), true);
  assert.equal(isArchitectureSource("app/main.py"), true);
  assert.equal(isArchitectureSource("src/a.test.ts"), false);
  assert.equal(isArchitectureSource("src/__tests__/a.ts"), false);
  assert.equal(isArchitectureSource("src/types.d.ts"), false);
  assert.equal(isArchitectureSource("README.md"), false);
});

test("builds the import graph and classifies roles", () => {
  const r = analyzeArchitecture(layered, { findings: [], secrets: [] });
  assert.equal(r.stats.sourceFiles, 7, "test file and package.json excluded");
  assert.equal(r.stats.imports, 7);
  assert.equal(r.stats.cycles, 0);
  assert.equal(r.stats.layerViolations, 0);
  const role = (id: string) => r.modules.find((m) => m.id === id)?.role;
  assert.equal(role("src/routes"), "entry");
  assert.equal(role("src/db"), "data");
  assert.equal(r.fragility.grade, "solide");
});

test("blast radius: who is compromised, through which entry points, which assets", () => {
  const r = analyzeArchitecture(layered, { findings: [sqli], secrets: [] });
  const b = r.blast[0]!;
  assert.equal(b.kind, "finding");
  assert.equal(b.module, "src/services");
  assert.deepEqual(b.entryPoints.sort(), ["src/routes/users.ts", "src/server.ts"]);
  assert.ok(b.assets.some((a) => a.kind === "data" && a.file === "src/db/client.ts"), "reaches the database");
  assert.ok(b.assets.some((a) => a.kind === "config"), "reaches the configuration");
  assert.ok(b.exposedModules.includes("src/routes"));
  assert.ok(b.impactScore >= 45, `high-severity, exposed and reaching data: ${b.impactScore}`);
  assert.match(b.narrative, /point\(s\) d'entrée/);
  // The orders route does not depend on the vulnerable code.
  assert.ok(!b.entryPoints.includes("src/routes/orders.ts"));
});

test("an unreachable vulnerability weighs less than an exposed one", () => {
  const files = [...layered, f("src/services/legacy.ts", `export const x = (q) => q;`)];
  const exposed = analyzeArchitecture(files, { findings: [sqli], secrets: [] }).blast[0]!;
  const isolated = analyzeArchitecture(files, {
    findings: [{ ...sqli, filePath: "src/services/legacy.ts" }],
    secrets: [],
  }).blast[0]!;
  assert.equal(isolated.entryPoints.length, 0);
  assert.ok(isolated.impactScore < exposed.impactScore);
});

test("cycles, layer violations and tangles raise fragility and produce a plan", () => {
  const messy = [
    f("src/server.ts", `import "./routes/a";\nimport "./routes/b";\napp.listen(1);`),
    f("src/routes/a.ts", `import { s } from "../services/s";\nimport { q } from "../db/repo";\nrouter.get("/a", s);`),
    f("src/routes/b.ts", `import { t } from "../services/t";\nrouter.get("/b", t);`),
    // s ⇄ t: a cycle.
    f("src/services/s.ts", `import { t } from "./t";\nexport const s = () => t();`),
    f("src/services/t.ts", `import { s } from "./s";\nexport const t = () => s();`),
    // The data layer imports a route: inverted dependency.
    f("src/db/repo.ts", `import "../routes/b";\nexport const q = () => prisma.user.findMany();`),
  ];
  const r = analyzeArchitecture(messy, { findings: [], secrets: [] });
  assert.ok(r.stats.cycles >= 1);
  assert.ok(r.stats.filesInCycles >= 2);
  assert.ok(r.stats.layerViolations >= 1);
  assert.ok(r.fragility.score > 20, `messy architecture scores ${r.fragility.score}`);
  assert.notEqual(r.fragility.grade, "solide");
  const ids = r.proposals.map((p) => p.id);
  assert.ok(ids.some((i) => i.startsWith("cycle-")), "proposes breaking the cycle");
  assert.ok(ids.includes("layers"), "proposes fixing the inverted dependency");
  for (const p of r.proposals) {
    assert.ok(p.actions.length > 0 && p.advantage.length > 0, "every proposal is actionable and says what it brings");
  }
  assert.ok(r.fragility.projectedScore < r.fragility.score);
  assert.ok(r.modules.find((m) => m.id === "src/services")?.inCycle, "the cyclic module is flagged on the graph");
  assert.ok(r.edges.find((e) => e.from === "src/db" && e.to === "src/routes")?.violation, "inverted edge flagged");
});

test("resolves aliases, workspace packages and Python imports", () => {
  const r = analyzeArchitecture(
    [
      f("apps/web/src/app/page.tsx", `import { api } from "@/lib/api";\nimport { schema } from "@acme/shared";`),
      f("apps/web/src/lib/api.ts", `export const api = 1;`),
      f("packages/shared/package.json", JSON.stringify({ name: "@acme/shared" })),
      f("packages/shared/src/index.ts", `export * from "./schema.js";`),
      f("packages/shared/src/schema.ts", `export const schema = 1;`),
      f("svc/app/main.py", `from app.db import session\nfrom .models import User\nimport os\n`),
      f("svc/app/db.py", `import sqlalchemy\n`),
      f("svc/app/models.py", `from app import db\n`),
    ],
    { findings: [], secrets: [] },
  );
  // page→api, page→shared index, index→schema, main→db, main→models, models→db.
  assert.equal(r.stats.imports, 6);
  assert.ok(r.stats.languages.includes("Python"));
});

test("secrets get a direct-access narrative and a dedicated proposal", () => {
  const r = analyzeArchitecture(layered, {
    findings: [],
    secrets: [{ secretType: "stripe_live_key", location: "src/config.ts:1", maskedPreview: "sk_…", severity: "critical" }],
  });
  const b = r.blast[0]!;
  assert.equal(b.kind, "secret");
  assert.equal(b.level, "critique");
  assert.match(b.narrative, /accès direct/);
  assert.ok(r.proposals.some((p) => p.id === "secrets"));
});

test("display stays readable on large repositories", () => {
  const files = Array.from({ length: 400 }, (_, i) =>
    f(`src/m${i % 60}/sub${i % 7}/f${i}.ts`, i ? `import "../../m${(i + 1) % 60}/sub${(i + 1) % 7}/f${i + 1}";` : ""),
  );
  const t = Date.now();
  const r = analyzeArchitecture(files, { findings: [], secrets: [] });
  assert.ok(r.modules.length <= 36, `${r.modules.length} modules`);
  assert.ok(r.edges.length <= 250);
  assert.ok(Date.now() - t < 2000);
});
