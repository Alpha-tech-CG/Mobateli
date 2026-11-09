import { test } from "node:test";
import assert from "node:assert/strict";
import type { Block } from "./audit-report.js";
import { expertBlocks, maturity, remediationPlan, type ExpertInput } from "./expert.js";
import { BACKUP_DOMAINS, CODE_DOMAINS, INFRA_DOMAINS, backupItems, backupRescore, codeItems, codeRescore, infraItems, infraRescore } from "./expert-mappings.js";

const section = (blocks: Block[], title: string) => blocks.findIndex((b) => b.kind === "section" && b.title === title);

test("server: summary, domains, prioritised plan grouped by action, frameworks", () => {
  const findings = [
    { checkId: "docker.privileged.cadvisor", category: "docker", severity: "critical" as const, title: "Conteneur « cadvisor » en mode privilégié" },
    { checkId: "docker.limits.api", category: "docker", severity: "low" as const, title: "Pas de limite mémoire sur « api »" },
    { checkId: "docker.limits.db", category: "docker", severity: "low" as const, title: "Pas de limite mémoire sur « db »" },
    { checkId: "ssh.password_auth", category: "ssh", severity: "high" as const, title: "Authentification SSH par mot de passe active" },
  ];
  const items = infraItems(findings, [{ title: "Internet -> cadvisor -> serveur", checkIds: ["docker.privileged.cadvisor"] }]);
  const input: ExpertInput = { scale: "security", score: infraRescore(items), items, domains: INFRA_DOMAINS, rescore: infraRescore, subject: "le serveur vps" };
  const plan = remediationPlan(input);

  assert.equal(plan[0]!.key, "docker.privileged", "critical and chained first");
  assert.equal(plan[0]!.priority, 0);
  assert.ok(plan[0]!.gain > 0);
  const limits = plan.find((p) => p.key === "docker.limits")!;
  assert.deepEqual(limits.subjects, ["api", "db"], "same action across containers is one plan line");

  const blocks = expertBlocks(input);
  for (const title of ["Synthèse pour la direction", "Niveau de maîtrise par domaine", "Plan de remédiation priorisé", "Correspondance avec les référentiels"]) {
    assert.ok(section(blocks, title) >= 0, title);
  }
  const summary = blocks.find((b) => b.kind === "bullets")!;
  assert.ok(summary.kind === "bullets" && summary.items.some((s) => s.includes("insuffisante")));
  assert.ok(summary.kind === "bullets" && summary.items.some((s) => /Risque critique — prise de contrôle/.test(s)));
  const bars = blocks.find((b) => b.kind === "bars")!;
  assert.ok(bars.kind === "bars" && bars.items.find((d) => d.label === "Chiffrement (TLS / HTTP)")!.value === 100);
  const mapping = blocks[section(blocks, "Correspondance avec les référentiels") + 1]!;
  assert.ok(mapping.kind === "table" && mapping.rows.some((r) => r[0] === "CIS Docker Benchmark" && r[3] === "Non conforme"));
});

test("pull request: risk scale — a fix lowers the score, secrets map to CWE-798", () => {
  const items = codeItems(
    [{ secretType: "Stripe secret key", location: "src/pay.ts:12", severity: "high" }],
    [{ type: "sast", severity: "high", title: "Injection SQL", ruleId: "SQLI" }],
    [{ name: "lodahs", version: "1.0.0", riskLevel: "critical" }],
  );
  const input: ExpertInput = { scale: "risk", score: codeRescore(items), items, domains: CODE_DOMAINS, rescore: codeRescore, subject: "cette pull request" };
  assert.equal(input.score, 100);
  const plan = remediationPlan(input);
  assert.ok(plan.every((p) => p.gain >= 0));
  const refs = items.flatMap((i) => i.refs);
  assert.ok(refs.includes("MITRE CWE · CWE-798 Identifiants codés en dur"));
  assert.ok(refs.includes("MITRE CWE · CWE-89 Injection SQL"));
});

test("clean subject: positive summary and empty plan", () => {
  const blocks = expertBlocks({ scale: "security", score: 100, items: [], domains: BACKUP_DOMAINS, rescore: backupRescore, subject: "la sauvegarde db" });
  const summary = blocks.find((b) => b.kind === "bullets")!;
  assert.ok(summary.kind === "bullets" && /Aucun risque ouvert/.test(summary.items[0]!));
  assert.equal(section(blocks, "Plan de remédiation priorisé"), -1);
  assert.equal(maturity([]), 100);
});

test("backup checks map to their domains", () => {
  const items = backupItems([
    { id: "restore_test", ok: false, severity: "critical", label: "Restauration testée" },
    { id: "immutability", ok: false, severity: "high", label: "Copie immuable" },
    { id: "exists", ok: true, severity: "critical", label: "Sauvegarde présente" },
  ]);
  assert.deepEqual(items.map((i) => i.domain), ["Restauration", "Isolement (rançongiciel)"]);
  assert.equal(backupRescore(items), 100 - 30 - 12);
});
