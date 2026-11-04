import { test, mock } from "node:test";
import assert from "node:assert/strict";
import type { AppConfig } from "../config.js";
import type { ReportDocument } from "./audit-report.js";
import { aiNarrative, cleanNarrative, narrativeInput, withNarrative } from "./ai-narrative.js";

const report: ReportDocument = {
  type: "server",
  heading: "RAPPORT D'AUDIT D'INFRASTRUCTURE",
  eyebrow: "INFRA SHIELD",
  title: "Audit de serveur",
  subtitle: "vps-1",
  organization: "Acme",
  facts: [],
  kpis: [{ label: "Score de sécurité / 100", value: 38 }],
  verdict: { label: "À durcir", tone: "bad", text: "Score 38/100." },
  blocks: [
    { kind: "section", title: "Synthèse pour la direction" },
    { kind: "bullets", items: ["La posture est insuffisante."] },
    { kind: "section", title: "Plan de remédiation priorisé" },
    { kind: "table", columns: [], rows: [["Immédiat (24 h)", "Supprimer le mode privilégié", "moyen", "+7 pts", "critique"]] },
  ],
};
const config = (over: Partial<AppConfig> = {}) =>
  ({ GEMINI_API_KEY: "test-key", GEMINI_MODEL: "gemini-3.5-flash", AI_NARRATIVE: "on", ...over }) as AppConfig;
const answer = (body: object) =>
  new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify(body) }] } }] }), { status: 200 });

test("only the report's own facts are sent to the model", () => {
  const data = narrativeInput(report);
  assert.deepEqual(data.planDeRemediation, ["Immédiat (24 h) | Supprimer le mode privilégié | effort moyen | gain +7 pts"]);
  assert.deepEqual(data.synthese, ["La posture est insuffisante."]);
});

test("generated text loses links, markup and control characters", () => {
  assert.equal(cleanNarrative("**Voir** https://evil.example/x et www.evil.example `ok`\u0007 fin"), "Voir et ok fin");
});

test("falls back to the next model when one is overloaded, then inserts the analysis after the summary", async () => {
  const calls: string[] = [];
  const fetchMock = mock.method(globalThis, "fetch", async (url: string | URL) => {
    calls.push(String(url));
    if (calls.length === 1) return new Response("{}", { status: 503 });
    return answer({ analyse: "Le serveur est exposé.", impactMetier: "Risque de perte de données.", avis: "Agir sous 24 h." });
  });
  try {
    const n = await aiNarrative(config(), report);
    assert.equal(n?.model, "gemini-3.8-flash");
    assert.match(calls[0]!, /gemini-3\.5-flash:generateContent/);
    const out = withNarrative(report, n);
    const i = out.blocks.findIndex((b) => b.kind === "bullets");
    assert.ok(out.blocks[i + 1]?.kind === "section" && out.blocks[i + 1]!.kind === "section");
    const prose = out.blocks.find((b) => b.kind === "prose");
    assert.ok(prose?.kind === "prose" && prose.items[0]!.text === "Le serveur est exposé.");
    assert.ok(out.blocks.some((b) => b.kind === "note" && /IA \(Gemini 3\.8 Flash\)/.test(b.text)));
  } finally {
    fetchMock.mock.restore();
  }
});

test("no key, AI disabled or a broken answer: the report is unchanged", async () => {
  assert.equal(await aiNarrative(config({ GEMINI_API_KEY: undefined }), report), null);
  assert.equal(await aiNarrative(config({ AI_NARRATIVE: "off" }), report), null);
  const fetchMock = mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: "{tronqué" }] } }] }), { status: 200 }));
  try {
    const n = await aiNarrative(config(), report);
    assert.equal(n, null);
    assert.equal(withNarrative(report, n), report);
  } finally {
    fetchMock.mock.restore();
  }
});
