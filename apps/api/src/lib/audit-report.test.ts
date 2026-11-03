import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import forge from "node-forge";
import { renderSignedReport } from "./audit-report.js";
import { organizationDocument } from "./report-documents.js";
import { generateIdentity } from "./report-signing.js";
import type { EvidencePack } from "./evidence.js";

const now = new Date().toISOString();
const pack: EvidencePack = {
  organization: { id: "o", name: "Acme" },
  generatedAt: now,
  filters: {},
  summary: {
    pullRequests: 1,
    byStatus: { blocked: 1 },
    findingsBySeverity: { high: 1 },
    secretsBlocked: 1,
    dependenciesRefused: 0,
    remediationIssues: 0,
    auditEvents: 1,
  },
  pullRequests: [
    {
      repository: "acme/api",
      number: 7,
      title: "feat: login",
      author: "dev",
      aiGenerated: true,
      riskScore: 85,
      status: "blocked",
      counts: { findings: 1, secrets: 1, dependencies: 0 },
      createdAt: now,
    },
  ],
  auditEvents: [
    { createdAt: now, actorType: "system", actorId: null, action: "pr.analyzed", resourceType: "pull_request", resourceId: null, metadata: null },
  ],
  policies: [],
  infrastructure: [],
  bruteForce: { policies: [], tests: [] },
  backups: [],
};

// The signature is zero-padded: parse the DER without requiring every byte.
const fromDer = forge.asn1.fromDer as unknown as (bytes: string, options: { parseAllBytes: boolean }) => forge.asn1.Asn1;

/** Checks the embedded PKCS#7 signature the way a PDF reader does. */
function verifySignature(pdf: Buffer): { digestOk: boolean; signatureOk: boolean } {
  const latin = pdf.toString("latin1");
  const m = /\/ByteRange \[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/.exec(latin);
  assert.ok(m, "ByteRange present");
  const [a, b, c, d] = m.slice(1).map(Number) as [number, number, number, number];
  const signed = Buffer.concat([pdf.subarray(a, a + b), pdf.subarray(c, c + d)]);
  const hex = latin.slice(a + b + 1, c - 1); // strip < and >
  const der = forge.util.hexToBytes(hex.replace(/(00)+$/, ""));
  const p7 = forge.pkcs7.messageFromAsn1(fromDer(der, { parseAllBytes: false })) as unknown as {
    certificates: forge.pki.Certificate[];
    rawCapture: { authenticatedAttributes: forge.asn1.Asn1[]; signature: string };
  };
  const attrs = p7.rawCapture.authenticatedAttributes;
  const mdAttr = attrs.find(
    (x) => forge.asn1.derToOid((x.value as forge.asn1.Asn1[])[0]!.value as string) === forge.pki.oids.messageDigest,
  )!;
  const md = ((mdAttr.value as forge.asn1.Asn1[])[1]!.value as forge.asn1.Asn1[])[0]!.value as string;
  const digestOk = md === createHash("sha256").update(signed).digest().toString("latin1");

  const set = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, attrs);
  const attrsDigest = forge.md.sha256.create().update(forge.asn1.toDer(set).getBytes());
  const key = p7.certificates[0]!.publicKey as forge.pki.rsa.PublicKey;
  const signatureOk = key.verify(attrsDigest.digest().bytes(), p7.rawCapture.signature);
  return { digestOk, signatureOk };
}

test("audit report is a branded, signed PDF whose signature covers the file", async () => {
  const stored = generateIdentity();
  const { pdf, sha256 } = await renderSignedReport(organizationDocument(pack), {
    reportId: "3f2a9c1e-7b4d-4e8a-9f10-2c6d8e4b1a77",
    verifyUrl: "https://app.codegate.test/verify/3f2a9c1e-7b4d-4e8a-9f10-2c6d8e4b1a77",
    generatedBy: "Alice <alice@acme.test>",
    identity: {
      p12: Buffer.from(stored.p12, "base64"),
      passphrase: stored.passphrase,
      fingerprint: stored.fingerprint,
      subject: stored.subject,
      notAfter: stored.notAfter,
      source: "platform",
    },
  });
  assert.equal(pdf.subarray(0, 5).toString(), "%PDF-");
  assert.equal(sha256, createHash("sha256").update(pdf).digest("hex"));
  assert.match(pdf.toString("latin1"), /adbe\.pkcs7\.detached/);
  assert.match(stored.fingerprint, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);

  assert.deepEqual(verifySignature(pdf), { digestOk: true, signatureOk: true });

  // One altered byte in the signed range breaks the digest.
  const tampered = Buffer.from(pdf);
  const at = tampered.indexOf("(CodeGate)", 0, "latin1");
  tampered[at + 1] = "X".charCodeAt(0);
  assert.equal(verifySignature(tampered).digestOk, false);
});
