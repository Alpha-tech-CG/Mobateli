import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import PDFDocument from "pdfkit";
import QRCode from "qrcode";
import { SignPdf } from "@signpdf/signpdf";
import { P12Signer } from "@signpdf/signer-p12";
import { pdfkitAddPlaceholder } from "@signpdf/placeholder-pdfkit";
import type { EvidencePack } from "./evidence.js";
import type { SigningIdentity } from "./report-signing.js";

/**
 * Signed audit report (cahier §5.8, US07): the evidence pack laid out as a
 * branded PDF — CodeGate header and logo on every page, report number and
 * pagination in the footer — then signed electronically (PKCS#7 detached,
 * SHA-256) so any PDF reader shows whether the file was altered. A QR code
 * points to the public page that checks the copy against CodeGate's register.
 */

const BRAND = { brick: "#BB3E2C", dark: "#111111", ink: "#1F1F1F", muted: "#6B6B6B", line: "#E4E1DC", soft: "#F6F4F1" };
const PAGE = { width: 595.28, height: 841.89, margin: 48, headerHeight: 64, footerHeight: 36 };
const CONTENT_WIDTH = PAGE.width - PAGE.margin * 2;

const STATUS_FR: Record<string, string> = {
  pending: "En attente",
  analyzing: "En cours",
  passed: "Validée",
  warning: "Avertissement",
  blocked: "Bloquée",
  escalated: "Escaladée",
};
const SEVERITY_FR: Record<string, string> = {
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
  info: "Info",
};

let logo: Buffer | null | undefined;
function logoBytes(): Buffer | null {
  if (logo === undefined) {
    try {
      logo = readFileSync(new URL("./assets/codegate-logo.png", import.meta.url));
    } catch {
      logo = null; // the report stays valid without the image
    }
  }
  return logo;
}

/** pdfkit's opened image (openImage is untyped in @types/pdfkit). */
type ImageSrc = Parameters<PDFKit.PDFDocument["image"]>[0];

export interface ReportMeta {
  reportId: string;
  verifyUrl: string;
  generatedBy: string;
  identity: SigningIdentity;
  signingTime?: Date;
}

const fmtDate = (iso: string | null | undefined) =>
  iso
    ? new Date(iso).toLocaleString("fr-FR", { timeZone: "Europe/Paris", dateStyle: "medium", timeStyle: "short" })
    : "—";
const shortId = (id: string) => id.slice(0, 8).toUpperCase();

/** Renders and signs the report. Returns the final file and its SHA-256. */
export async function renderSignedReport(
  pack: EvidencePack,
  meta: ReportMeta,
): Promise<{ pdf: Buffer; sha256: string }> {
  const signingTime = meta.signingTime ?? new Date();
  const qr = await QRCode.toBuffer(meta.verifyUrl, {
    type: "png",
    margin: 1,
    width: 220,
    errorCorrectionLevel: "M",
    color: { dark: BRAND.dark, light: "#FFFFFF" },
  });
  const unsigned = await render(pack, meta, qr, signingTime);
  const signer = new P12Signer(meta.identity.p12, { passphrase: meta.identity.passphrase });
  const pdf = await new SignPdf().sign(unsigned, signer, signingTime);
  return { pdf, sha256: createHash("sha256").update(pdf).digest("hex") };
}

function render(pack: EvidencePack, meta: ReportMeta, qr: Buffer, signingTime: Date): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: "A4",
      bufferPages: true,
      margins: {
        top: PAGE.headerHeight + 28,
        bottom: PAGE.footerHeight + 24,
        left: PAGE.margin,
        right: PAGE.margin,
      },
      info: {
        Title: `Rapport d'audit de sécurité — ${pack.organization.name}`,
        Author: "CodeGate",
        Subject: `Rapport ${meta.reportId}`,
        Keywords: "CodeGate, audit, sécurité, preuves, conformité",
        Creator: "CodeGate",
        Producer: "CodeGate",
      },
    });
    const chunks: Buffer[] = [];
    doc.on("data", (c: Buffer) => chunks.push(c));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    // Embedded once, drawn on every page.
    const bytes = logoBytes();
    const img = bytes ? (doc as unknown as { openImage(src: Buffer): ImageSrc }).openImage(bytes) : null;
    const header = () => drawHeader(doc, pack, meta, img);
    doc.on("pageAdded", header);
    header();

    cover(doc, pack, meta);
    prSection(doc, pack);
    infraSection(doc, pack);
    bruteForceSection(doc, pack);
    backupSection(doc, pack);
    policySection(doc, pack);
    auditSection(doc, pack);
    signatureSection(doc, meta, qr, signingTime);

    // Footer on every page, now that the page count is known.
    const range = doc.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i++) {
      doc.switchToPage(i);
      drawFooter(doc, meta, i + 1, range.count);
    }

    // Signature field (invisible widget: the visible block is drawn above).
    doc.switchToPage(range.start + range.count - 1);
    // v4 ends the signature and widget refs itself; pdfkit ends the AcroForm.
    pdfkitAddPlaceholder({
      pdf: doc,
      pdfBuffer: Buffer.alloc(0),
      reason: `Rapport d'audit CodeGate ${meta.reportId}`,
      contactInfo: meta.verifyUrl,
      name: "CodeGate",
      location: "CodeGate — plateforme de sécurité",
      signingTime,
      appName: "CodeGate",
    });
    doc.end();
  });
}

// ---------------------------------------------------------------- layout --

function drawHeader(doc: PDFKit.PDFDocument, pack: EvidencePack, meta: ReportMeta, img: ImageSrc | null) {
  const { x, y } = doc;
  doc.save();
  doc.rect(0, 0, PAGE.width, PAGE.headerHeight).fill(BRAND.dark);
  doc.rect(0, PAGE.headerHeight, PAGE.width, 3).fill(BRAND.brick);
  let textX = PAGE.margin;
  if (img) {
    doc.image(img, PAGE.margin, 14, { fit: [36, 36] });
    textX += 46;
  }
  doc.fillColor("#FFFFFF").font("Helvetica-Bold").fontSize(16).text("CodeGate", textX, 18, { lineBreak: false });
  doc.fillColor("#BDBDBD").font("Helvetica").fontSize(8.5)
    .text("Security gate for AI-generated code", textX, 38, { lineBreak: false });
  const right = PAGE.width - PAGE.margin - 220;
  doc.fillColor("#FFFFFF").font("Helvetica-Bold").fontSize(9)
    .text("RAPPORT D'AUDIT DE SÉCURITÉ", right, 19, { width: 220, align: "right", lineBreak: false });
  doc.fillColor("#BDBDBD").font("Helvetica").fontSize(8.5)
    .text(`${pack.organization.name} · N° ${shortId(meta.reportId)}`, right, 33, {
      width: 220,
      align: "right",
      lineBreak: false,
      ellipsis: true,
    });
  doc.restore();
  doc.x = x;
  doc.y = y;
}

function drawFooter(doc: PDFKit.PDFDocument, meta: ReportMeta, page: number, pages: number) {
  const bottom = doc.page.margins.bottom;
  doc.page.margins.bottom = 0; // writing in the margin must not add a page
  const y = PAGE.height - PAGE.footerHeight;
  doc.save();
  doc.moveTo(PAGE.margin, y).lineTo(PAGE.width - PAGE.margin, y).lineWidth(0.5).stroke(BRAND.line);
  doc.fillColor(BRAND.muted).font("Helvetica").fontSize(7.5);
  doc.text(
    `Rapport N° ${shortId(meta.reportId)} · Signé électroniquement par CodeGate · Vérifiable en ligne (QR code en dernière page)`,
    PAGE.margin,
    y + 9,
    { width: CONTENT_WIDTH - 70, lineBreak: false, ellipsis: true },
  );
  doc.text(`Page ${page} / ${pages}`, PAGE.width - PAGE.margin - 70, y + 9, {
    width: 70,
    align: "right",
    lineBreak: false,
  });
  doc.restore();
  doc.page.margins.bottom = bottom;
}

function ensureSpace(doc: PDFKit.PDFDocument, height: number) {
  if (doc.y + height > PAGE.height - doc.page.margins.bottom) doc.addPage();
}

function sectionTitle(doc: PDFKit.PDFDocument, title: string, subtitle?: string) {
  ensureSpace(doc, 70);
  doc.moveDown(0.8);
  const y = doc.y;
  doc.rect(PAGE.margin, y + 1, 3, 13).fill(BRAND.brick);
  doc.fillColor(BRAND.ink).font("Helvetica-Bold").fontSize(12.5).text(title, PAGE.margin + 10, y, { width: CONTENT_WIDTH - 10 });
  if (subtitle) {
    doc.fillColor(BRAND.muted).font("Helvetica").fontSize(8.5).text(subtitle, PAGE.margin + 10, doc.y + 1, {
      width: CONTENT_WIDTH - 10,
    });
  }
  doc.x = PAGE.margin;
  doc.moveDown(0.5);
}

function note(doc: PDFKit.PDFDocument, text: string) {
  doc.fillColor(BRAND.muted).font("Helvetica-Oblique").fontSize(8.5).text(text, PAGE.margin, doc.y, { width: CONTENT_WIDTH });
  doc.font("Helvetica");
}

interface Column {
  label: string;
  width: number; // fraction of the content width
  align?: "left" | "right" | "center";
}

/** Zebra table that repeats its header row after a page break. */
function table(doc: PDFKit.PDFDocument, columns: Column[], rows: string[][], fontSize = 8) {
  const widths = columns.map((c) => c.width * CONTENT_WIDTH);
  const pad = 5;
  const headerRow = () => {
    const y = doc.y;
    doc.rect(PAGE.margin, y, CONTENT_WIDTH, 18).fill(BRAND.dark);
    let x = PAGE.margin;
    doc.fillColor("#FFFFFF").font("Helvetica-Bold").fontSize(7.5);
    columns.forEach((c, i) => {
      doc.text(c.label.toUpperCase(), x + pad, y + 5.5, {
        width: widths[i]! - pad * 2,
        align: c.align ?? "left",
        lineBreak: false,
        ellipsis: true,
      });
      x += widths[i]!;
    });
    doc.y = y + 18;
  };

  ensureSpace(doc, 40);
  headerRow();
  doc.font("Helvetica").fontSize(fontSize);
  rows.forEach((row, r) => {
    const height =
      Math.max(...row.map((cell, i) => doc.heightOfString(cell, { width: widths[i]! - pad * 2 }))) + pad * 2;
    if (doc.y + height > PAGE.height - doc.page.margins.bottom) {
      doc.addPage();
      headerRow();
      doc.font("Helvetica").fontSize(fontSize);
    }
    const y = doc.y;
    if (r % 2 === 1) doc.rect(PAGE.margin, y, CONTENT_WIDTH, height).fill(BRAND.soft);
    let x = PAGE.margin;
    doc.fillColor(BRAND.ink);
    row.forEach((cell, i) => {
      doc.text(cell, x + pad, y + pad, { width: widths[i]! - pad * 2, align: columns[i]!.align ?? "left" });
      x += widths[i]!;
    });
    doc.moveTo(PAGE.margin, y + height).lineTo(PAGE.margin + CONTENT_WIDTH, y + height).lineWidth(0.4).stroke(BRAND.line);
    doc.y = y + height;
  });
  doc.x = PAGE.margin;
}

// -------------------------------------------------------------- sections --

function cover(doc: PDFKit.PDFDocument, pack: EvidencePack, meta: ReportMeta) {
  doc.fillColor(BRAND.brick).font("Helvetica-Bold").fontSize(9).text("DOSSIER DE PREUVES DE SÉCURITÉ", PAGE.margin);
  doc.moveDown(0.2);
  doc.fillColor(BRAND.ink).font("Helvetica-Bold").fontSize(22).text("Rapport d'audit de sécurité");
  doc.fillColor(BRAND.muted).font("Helvetica").fontSize(11).text(pack.organization.name);
  doc.moveDown(0.9);

  const period =
    pack.filters.from || pack.filters.to
      ? `du ${fmtDate(pack.filters.from ?? null)} au ${pack.filters.to ? fmtDate(pack.filters.to) : "jour de l'export"}`
      : "toute la période";
  const facts: [string, string][] = [
    ["Numéro du rapport", meta.reportId],
    ["Organisation", pack.organization.name],
    ["Période couverte", period],
    ["Généré le", fmtDate(pack.generatedAt)],
    ["Généré par", meta.generatedBy],
    ["Seuil de sévérité", pack.filters.severityThreshold ? SEVERITY_FR[pack.filters.severityThreshold]! : "toutes"],
  ];
  const top = doc.y;
  const rowH = 17;
  doc.rect(PAGE.margin, top, CONTENT_WIDTH, facts.length * rowH + 12).fill(BRAND.soft);
  facts.forEach(([k, v], i) => {
    const y = top + 6 + i * rowH + 4;
    doc.fillColor(BRAND.muted).font("Helvetica").fontSize(8.5).text(k, PAGE.margin + 12, y, { width: 130 });
    doc.fillColor(BRAND.ink).font(i === 0 ? "Courier" : "Helvetica-Bold").fontSize(9)
      .text(v, PAGE.margin + 150, y, { width: CONTENT_WIDTH - 162, lineBreak: false, ellipsis: true });
  });
  doc.y = top + facts.length * rowH + 12 + 16;
  doc.x = PAGE.margin;

  // Key figures.
  const s = pack.summary;
  const serious = (s.findingsBySeverity.critical ?? 0) + (s.findingsBySeverity.high ?? 0);
  const kpis: [string, number, boolean][] = [
    ["Pull requests analysées", s.pullRequests, false],
    ["Secrets interceptés", s.secretsBlocked, s.secretsBlocked > 0],
    ["Dépendances refusées", s.dependenciesRefused, s.dependenciesRefused > 0],
    ["Problèmes critiques / élevés", serious, serious > 0],
  ];
  const gap = 10;
  const w = (CONTENT_WIDTH - gap * (kpis.length - 1)) / kpis.length;
  const ky = doc.y;
  kpis.forEach(([label, value, alert], i) => {
    const x = PAGE.margin + i * (w + gap);
    doc.roundedRect(x, ky, w, 62, 4).lineWidth(0.8).stroke(BRAND.line);
    doc.rect(x, ky, w, 3).fill(alert ? BRAND.brick : BRAND.dark);
    doc.fillColor(alert ? BRAND.brick : BRAND.ink).font("Helvetica-Bold").fontSize(20)
      .text(String(value), x + 10, ky + 13, { width: w - 20, lineBreak: false });
    doc.fillColor(BRAND.muted).font("Helvetica").fontSize(8).text(label, x + 10, ky + 40, { width: w - 20 });
  });
  doc.y = ky + 62 + 14;
  doc.x = PAGE.margin;

  const statuses = Object.entries(s.byStatus)
    .map(([k, v]) => `${STATUS_FR[k] ?? k} : ${v}`)
    .join(" · ");
  const severities = ["critical", "high", "medium", "low", "info"]
    .filter((k) => s.findingsBySeverity[k])
    .map((k) => `${SEVERITY_FR[k]} : ${s.findingsBySeverity[k]}`)
    .join(" · ");
  doc.fillColor(BRAND.ink).font("Helvetica").fontSize(9);
  doc.text(`Décisions : ${statuses || "aucune pull request sur la période"}`, { width: CONTENT_WIDTH });
  doc.text(`Problèmes de code par sévérité (hors faux positifs) : ${severities || "aucun"}`, { width: CONTENT_WIDTH });
  doc.text(`Issues de remédiation ouvertes : ${s.remediationIssues} · Événements d'audit : ${s.auditEvents}`, {
    width: CONTENT_WIDTH,
  });
}

function prSection(doc: PDFKit.PDFDocument, pack: EvidencePack) {
  sectionTitle(
    doc,
    "Décisions par pull request",
    "Chaque pull request est analysée avant fusion : secrets, dépendances, code et instructions cachées.",
  );
  if (!pack.pullRequests.length) return note(doc, "Aucune pull request analysée sur la période.");
  const rows = pack.pullRequests.slice(0, 200).map((pr) => [
    `${pr.repository} #${pr.number}${pr.aiGenerated ? "  (IA)" : ""}`,
    pr.title,
    pr.riskScore === null ? "—" : `${pr.riskScore}/100`,
    STATUS_FR[pr.status] ?? pr.status,
    fmtDate(pr.createdAt),
  ]);
  table(
    doc,
    [
      { label: "Dépôt / PR", width: 0.24 },
      { label: "Titre", width: 0.34 },
      { label: "Risque", width: 0.09, align: "right" },
      { label: "Décision", width: 0.15 },
      { label: "Date", width: 0.18 },
    ],
    rows,
  );
  if (pack.pullRequests.length > 200) note(doc, `… et ${pack.pullRequests.length - 200} autres (export JSON pour la liste complète).`);
}

function infraSection(doc: PDFKit.PDFDocument, pack: EvidencePack) {
  if (!pack.infrastructure.length) return;
  sectionTitle(doc, "Infrastructure — Infra Shield", "Score de durcissement des serveurs audités et points restant à corriger.");
  table(
    doc,
    [
      { label: "Serveur", width: 0.26 },
      { label: "Environnement", width: 0.16 },
      { label: "Score", width: 0.1, align: "right" },
      { label: "Dernier audit", width: 0.2 },
      { label: "À corriger", width: 0.28 },
    ],
    pack.infrastructure.map((sv) => [
      sv.server,
      sv.environment,
      sv.securityScore === null ? "—" : `${sv.securityScore}/100`,
      fmtDate(sv.lastAuditAt),
      Object.entries(sv.openFindings).map(([k, v]) => `${SEVERITY_FR[k] ?? k} ${v}`).join(", ") || "rien",
    ]),
  );
}

function bruteForceSection(doc: PDFKit.PDFDocument, pack: EvidencePack) {
  const bf = pack.bruteForce;
  if (!bf.policies.length && !bf.tests.length) return;
  sectionTitle(doc, "Protection anti brute force — BruteForce Shield");
  if (bf.policies.length) {
    table(
      doc,
      [
        { label: "Point d'entrée", width: 0.4 },
        { label: "Échecs max", width: 0.2, align: "right" },
        { label: "Fenêtre", width: 0.2, align: "right" },
        { label: "Blocage", width: 0.2, align: "right" },
      ],
      bf.policies.map((p) => [p.endpoint, String(p.maxAttempts), `${p.windowSeconds} s`, `${p.lockoutSeconds} s`]),
    );
    doc.moveDown(0.6);
  }
  if (bf.tests.length) {
    table(
      doc,
      [
        { label: "Date", width: 0.2 },
        { label: "Cible", width: 0.4 },
        { label: "Test", width: 0.2 },
        { label: "Résultat", width: 0.2 },
      ],
      bf.tests.slice(0, 60).map((t) => [fmtDate(t.createdAt), `${t.target}${t.endpoint}`, t.testType, t.result]),
    );
  }
}

function backupSection(doc: PDFKit.PDFDocument, pack: EvidencePack) {
  if (!pack.backups.length) return;
  sectionTitle(doc, "Sauvegardes — Backup Shield", "Capacité de restauration, y compris face à un rançongiciel.");
  table(
    doc,
    [
      { label: "Sauvegarde", width: 0.22 },
      { label: "État", width: 0.12 },
      { label: "Récupération", width: 0.13, align: "right" },
      { label: "Dernière exécution", width: 0.17 },
      { label: "Restauration testée", width: 0.17 },
      { label: "À corriger", width: 0.19 },
    ],
    pack.backups.map((b) => [
      `${b.name} (${b.type})${b.ransomwareReady ? " · prête rançongiciel" : ""}`,
      b.status,
      `${b.recoveryScore}/100`,
      fmtDate(b.lastRunAt),
      fmtDate(b.lastRestoreTestAt),
      b.failedChecks.join(", ") || "rien",
    ]),
  );
}

function policySection(doc: PDFKit.PDFDocument, pack: EvidencePack) {
  if (!pack.policies.length) return;
  sectionTitle(doc, "Politiques de sécurité appliquées");
  table(
    doc,
    [
      { label: "Règle", width: 0.4 },
      { label: "Action", width: 0.2 },
      { label: "Seuil", width: 0.2 },
      { label: "Portée", width: 0.2 },
    ],
    pack.policies.map((p) => [
      p.rule,
      p.action,
      SEVERITY_FR[p.severityThreshold] ?? p.severityThreshold,
      p.scope === "repository" ? "dépôt" : "organisation",
    ]),
  );
}

function auditSection(doc: PDFKit.PDFDocument, pack: EvidencePack) {
  sectionTitle(
    doc,
    "Journal d'audit",
    `Extrait des ${Math.min(pack.auditEvents.length, 150)} événements les plus récents sur ${pack.auditEvents.length} (journal immuable ; export CSV pour l'intégralité).`,
  );
  if (!pack.auditEvents.length) return note(doc, "Aucun événement sur la période.");
  table(
    doc,
    [
      { label: "Horodatage", width: 0.22 },
      { label: "Acteur", width: 0.14 },
      { label: "Action", width: 0.38 },
      { label: "Ressource", width: 0.26 },
    ],
    pack.auditEvents.slice(0, 150).map((e) => [fmtDate(e.createdAt), e.actorType, e.action, e.resourceType]),
    7.5,
  );
}

function signatureSection(doc: PDFKit.PDFDocument, meta: ReportMeta, qr: Buffer, signingTime: Date) {
  ensureSpace(doc, 250);
  sectionTitle(doc, "Signature électronique");
  const top = doc.y;
  const height = 176;
  const qrSize = 118;
  doc.roundedRect(PAGE.margin, top, CONTENT_WIDTH, height, 5).lineWidth(1).stroke(BRAND.brick);
  doc.rect(PAGE.margin, top, CONTENT_WIDTH, 26).fill(BRAND.dark);
  doc.fillColor("#FFFFFF").font("Helvetica-Bold").fontSize(10)
    .text("Document signé électroniquement par CodeGate", PAGE.margin + 14, top + 8, { lineBreak: false });

  const textW = CONTENT_WIDTH - qrSize - 44;
  const lines: [string, string, string?][] = [
    ["Signataire", meta.identity.subject],
    ["Date de signature", fmtDate(signingTime.toISOString())],
    ["Méthode", "Signature PDF PKCS#7 détachée · SHA-256 · RSA"],
    ["Empreinte du certificat", meta.identity.fingerprint, "Courier"],
    ["Numéro du rapport", meta.reportId, "Courier"],
  ];
  let y = top + 38;
  for (const [k, v, font] of lines) {
    doc.fillColor(BRAND.muted).font("Helvetica").fontSize(7.5).text(k.toUpperCase(), PAGE.margin + 14, y, { width: textW });
    y = doc.y + 1;
    doc.fillColor(BRAND.ink).font(font ?? "Helvetica-Bold").fontSize(font ? 7 : 8.5).text(v, PAGE.margin + 14, y, { width: textW });
    y = doc.y + 5;
  }
  doc.image(qr, PAGE.margin + CONTENT_WIDTH - qrSize - 16, top + 36, { width: qrSize });
  doc.fillColor(BRAND.muted).font("Helvetica").fontSize(7)
    .text("Scannez pour vérifier", PAGE.margin + CONTENT_WIDTH - qrSize - 16, top + 36 + qrSize + 4, {
      width: qrSize,
      align: "center",
    });

  doc.y = top + height + 10;
  doc.x = PAGE.margin;
  doc.fillColor(BRAND.ink).font("Helvetica").fontSize(8.5).text(
    "La signature couvre l'intégralité du fichier : toute modification, même d'un caractère, la rend invalide " +
      "dans un lecteur PDF (Adobe Acrobat, Foxit…). L'empreinte SHA-256 du fichier émis est enregistrée dans le " +
      "registre CodeGate : déposez votre copie sur la page de vérification pour confirmer qu'elle est authentique et intacte.",
    { width: CONTENT_WIDTH },
  );
  doc.moveDown(0.3);
  doc.fillColor(BRAND.brick).font("Helvetica-Bold").fontSize(8.5).text(meta.verifyUrl, {
    width: CONTENT_WIDTH,
    link: meta.verifyUrl,
    underline: true,
  });
}
