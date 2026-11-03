import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import PDFDocument from "pdfkit";
import QRCode from "qrcode";
import { SignPdf } from "@signpdf/signpdf";
import { P12Signer } from "@signpdf/signer-p12";
import { pdfkitAddPlaceholder } from "@signpdf/placeholder-pdfkit";
import type { SigningIdentity } from "./report-signing.js";

/**
 * Signed audit reports (cahier §5.8, US07). Every report — whole
 * organization, one pull request, one repository scan, one server, one
 * brute-force target, one backup — shares the same frame: CodeGate header
 * and logo on every page, report number and pagination in the footer, and an
 * electronic signature (PKCS#7 detached, SHA-256) so any PDF reader shows
 * whether the file was altered. A QR code points to the public page that
 * checks the copy against CodeGate's register.
 */

const BRAND = { brick: "#BB3E2C", dark: "#111111", ink: "#1F1F1F", muted: "#6B6B6B", line: "#E4E1DC", soft: "#F6F4F1", ok: "#2E7A45", warn: "#B7791F" };
const PAGE = { width: 595.28, height: 841.89, margin: 48, headerHeight: 64, footerHeight: 36 };
const CONTENT_WIDTH = PAGE.width - PAGE.margin * 2;

export interface Column {
  label: string;
  width: number; // fraction of the content width
  align?: "left" | "right" | "center";
}

export type Block =
  | { kind: "section"; title: string; subtitle?: string }
  /** Starts a new part of the report on a fresh page. */
  | { kind: "chapter"; title: string; subtitle?: string }
  | { kind: "table"; columns: Column[]; rows: string[][]; fontSize?: number; empty?: string }
  | { kind: "text"; text: string }
  | { kind: "note"; text: string }
  | { kind: "bullets"; items: string[] }
  /** Horizontal 0–100 bars, e.g. maturity per domain. */
  | { kind: "bars"; items: { label: string; value: number; note?: string }[] };

export interface Kpi {
  label: string;
  value: string | number;
  alert?: boolean;
}

/** Content of one report; the frame and signature are added by the renderer. */
export interface ReportDocument {
  /** Registry type: organization, pull_request, repository_scan, server, bruteforce, backup. */
  type: string;
  /** Header label, e.g. "RAPPORT D'ANALYSE DE PULL REQUEST". */
  heading: string;
  eyebrow: string;
  title: string;
  subtitle: string;
  organization: string;
  subjectId?: string;
  subjectLabel?: string;
  facts: [string, string][];
  kpis: Kpi[];
  verdict?: { label: string; tone: "ok" | "warn" | "bad"; text: string };
  blocks: Block[];
}

export interface ReportMeta {
  reportId: string;
  verifyUrl: string;
  generatedBy: string;
  identity: SigningIdentity;
  signingTime?: Date;
}

/** pdfkit's opened image (openImage is untyped in @types/pdfkit). */
type ImageSrc = Parameters<PDFKit.PDFDocument["image"]>[0];

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

export const fmtDate = (value: string | Date | null | undefined) =>
  value
    ? new Date(value).toLocaleString("fr-FR", { timeZone: "Europe/Paris", dateStyle: "medium", timeStyle: "short" })
    : "—";
const shortId = (id: string) => id.slice(0, 8).toUpperCase();

/**
 * The standard PDF fonts only cover Windows-1252: arrows, comparison signs
 * and box-drawing characters would print as garbage, so they are spelled out.
 */
const REPLACEMENTS: Record<string, string> = { "→": "->", "←": "<-", "≥": ">=", "≤": "<=", "≠": "!=", "✓": "OK", "✗": "x", "─": "-", "…": "..." };
export function pdfSafe(text: string): string {
  return text.replace(/[^\u0000-ÿ€‚ƒ„†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ]/g, (c) => REPLACEMENTS[c] ?? "?");
}

function printable(report: ReportDocument): ReportDocument {
  const t = pdfSafe;
  return {
    ...report,
    heading: t(report.heading),
    eyebrow: t(report.eyebrow),
    title: t(report.title),
    subtitle: t(report.subtitle),
    organization: t(report.organization),
    facts: report.facts.map(([k, v]) => [t(k), t(v)]),
    kpis: report.kpis.map((k) => ({ ...k, label: t(k.label), value: typeof k.value === "string" ? t(k.value) : k.value })),
    ...(report.verdict ? { verdict: { ...report.verdict, label: t(report.verdict.label), text: t(report.verdict.text) } } : {}),
    blocks: report.blocks.map((b) =>
      b.kind === "table"
        ? { ...b, columns: b.columns.map((c) => ({ ...c, label: t(c.label) })), rows: b.rows.map((r) => r.map(t)), ...(b.empty ? { empty: t(b.empty) } : {}) }
        : b.kind === "section" || b.kind === "chapter"
          ? { ...b, title: t(b.title), ...(b.subtitle ? { subtitle: t(b.subtitle) } : {}) }
          : b.kind === "bullets"
            ? { ...b, items: b.items.map(t) }
            : b.kind === "bars"
              ? { ...b, items: b.items.map((i) => ({ ...i, label: t(i.label), ...(i.note ? { note: t(i.note) } : {}) })) }
              : { ...b, text: t(b.text) },
    ),
  };
}

/** Renders and signs the report. Returns the final file and its SHA-256. */
export async function renderSignedReport(
  report: ReportDocument,
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
  const unsigned = await render(printable(report), meta, qr, signingTime);
  const signer = new P12Signer(meta.identity.p12, { passphrase: meta.identity.passphrase });
  const pdf = await new SignPdf().sign(unsigned, signer, signingTime);
  return { pdf, sha256: createHash("sha256").update(pdf).digest("hex") };
}

function render(report: ReportDocument, meta: ReportMeta, qr: Buffer, signingTime: Date): Promise<Buffer> {
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
        Title: `${report.title} — ${report.subtitle}`,
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
    const header = () => drawHeader(doc, report, meta, img);
    doc.on("pageAdded", header);
    header();

    cover(doc, report, meta);
    for (const block of report.blocks) {
      if (block.kind === "section") sectionTitle(doc, block.title, block.subtitle);
      else if (block.kind === "chapter") chapter(doc, block.title, block.subtitle);
      else if (block.kind === "table") {
        if (block.rows.length) table(doc, block.columns, block.rows, block.fontSize);
        else note(doc, block.empty ?? "Rien à signaler.");
      } else if (block.kind === "text") text(doc, block.text);
      else if (block.kind === "bullets") bullets(doc, block.items);
      else if (block.kind === "bars") bars(doc, block.items);
      else note(doc, block.text);
    }
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
      reason: `${report.title} CodeGate ${meta.reportId}`,
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

function drawHeader(doc: PDFKit.PDFDocument, report: ReportDocument, meta: ReportMeta, img: ImageSrc | null) {
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
    .text("Security gate for all your code", textX, 38, { lineBreak: false });
  const right = PAGE.width - PAGE.margin - 260;
  doc.fillColor("#FFFFFF").font("Helvetica-Bold").fontSize(9)
    .text(report.heading, right, 19, { width: 260, align: "right", lineBreak: false, ellipsis: true });
  doc.fillColor("#BDBDBD").font("Helvetica").fontSize(8.5)
    .text(`${report.organization} · N° ${shortId(meta.reportId)}`, right, 33, {
      width: 260,
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

function chapter(doc: PDFKit.PDFDocument, title: string, subtitle?: string) {
  if (doc.y > doc.page.margins.top + 10) doc.addPage();
  doc.fillColor(BRAND.brick).font("Helvetica-Bold").fontSize(9).text("PARTIE 2", PAGE.margin, doc.y);
  doc.fillColor(BRAND.ink).font("Helvetica-Bold").fontSize(18).text(title, PAGE.margin, doc.y + 2, { width: CONTENT_WIDTH });
  if (subtitle) doc.fillColor(BRAND.muted).font("Helvetica").fontSize(9.5).text(subtitle, { width: CONTENT_WIDTH });
  const y = doc.y + 6;
  doc.moveTo(PAGE.margin, y).lineTo(PAGE.margin + CONTENT_WIDTH, y).lineWidth(1).stroke(BRAND.brick);
  doc.y = y + 8;
  doc.x = PAGE.margin;
}

function note(doc: PDFKit.PDFDocument, value: string) {
  doc.fillColor(BRAND.muted).font("Helvetica-Oblique").fontSize(8.5).text(value, PAGE.margin, doc.y, { width: CONTENT_WIDTH });
  doc.font("Helvetica");
}

function text(doc: PDFKit.PDFDocument, value: string) {
  doc.fillColor(BRAND.ink).font("Helvetica").fontSize(9).text(value, PAGE.margin, doc.y, { width: CONTENT_WIDTH });
  doc.moveDown(0.3);
}

function bullets(doc: PDFKit.PDFDocument, items: string[]) {
  doc.font("Helvetica").fontSize(9.5);
  for (const item of items) {
    const h = doc.heightOfString(item, { width: CONTENT_WIDTH - 14 });
    ensureSpace(doc, h + 6);
    const y = doc.y;
    doc.rect(PAGE.margin + 1, y + 4, 4, 4).fill(BRAND.brick);
    doc.fillColor(BRAND.ink).font("Helvetica").fontSize(9.5).text(item, PAGE.margin + 14, y, { width: CONTENT_WIDTH - 14 });
    doc.y += 4;
  }
  doc.x = PAGE.margin;
}

function bars(doc: PDFKit.PDFDocument, items: { label: string; value: number; note?: string }[]) {
  const labelW = 150;
  const noteW = 110;
  const barW = CONTENT_WIDTH - labelW - noteW - 40;
  for (const item of items) {
    ensureSpace(doc, 22);
    const y = doc.y;
    const v = Math.max(0, Math.min(100, item.value));
    const tone = v >= 80 ? BRAND.ok : v >= 50 ? BRAND.warn : BRAND.brick;
    doc.fillColor(BRAND.ink).font("Helvetica-Bold").fontSize(9).text(item.label, PAGE.margin, y + 2, { width: labelW, lineBreak: false, ellipsis: true });
    doc.rect(PAGE.margin + labelW, y + 2, barW, 10).fill(BRAND.soft);
    if (v > 0) doc.rect(PAGE.margin + labelW, y + 2, (barW * v) / 100, 10).fill(tone);
    doc.fillColor(tone).font("Helvetica-Bold").fontSize(9).text(`${v}`, PAGE.margin + labelW + barW + 6, y + 2, { width: 30, lineBreak: false });
    if (item.note)
      doc.fillColor(BRAND.muted).font("Helvetica").fontSize(8).text(item.note, PAGE.margin + CONTENT_WIDTH - noteW, y + 3, {
        width: noteW,
        align: "right",
        lineBreak: false,
        ellipsis: true,
      });
    doc.y = y + 20;
  }
  doc.x = PAGE.margin;
  doc.moveDown(0.3);
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

function cover(doc: PDFKit.PDFDocument, report: ReportDocument, meta: ReportMeta) {
  doc.fillColor(BRAND.brick).font("Helvetica-Bold").fontSize(9).text(report.eyebrow, PAGE.margin);
  doc.moveDown(0.2);
  doc.fillColor(BRAND.ink).font("Helvetica-Bold").fontSize(21).text(report.title, { width: CONTENT_WIDTH });
  doc.fillColor(BRAND.muted).font("Helvetica").fontSize(11).text(report.subtitle, { width: CONTENT_WIDTH });
  doc.moveDown(0.9);

  const facts: [string, string][] = [
    ["Numéro du rapport", meta.reportId],
    ["Organisation", report.organization],
    ...report.facts,
    ["Généré par", meta.generatedBy],
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

  if (report.verdict) {
    const tone = { ok: BRAND.ok, warn: BRAND.warn, bad: BRAND.brick }[report.verdict.tone];
    const vy = doc.y;
    doc.font("Helvetica").fontSize(9);
    const h = Math.max(40, doc.heightOfString(report.verdict.text, { width: CONTENT_WIDTH - 150 }) + 20);
    doc.rect(PAGE.margin, vy, CONTENT_WIDTH, h).fill(BRAND.soft);
    doc.rect(PAGE.margin, vy, 4, h).fill(tone);
    doc.fillColor(tone).font("Helvetica-Bold").fontSize(13)
      .text(report.verdict.label, PAGE.margin + 14, vy + h / 2 - 8, { width: 120, lineBreak: false, ellipsis: true });
    doc.fillColor(BRAND.ink).font("Helvetica").fontSize(9)
      .text(report.verdict.text, PAGE.margin + 140, vy + 10, { width: CONTENT_WIDTH - 150 });
    doc.y = vy + h + 14;
    doc.x = PAGE.margin;
  }

  if (report.kpis.length) {
    const kpis = report.kpis.slice(0, 4);
    const gap = 10;
    const w = (CONTENT_WIDTH - gap * (kpis.length - 1)) / kpis.length;
    const ky = doc.y;
    kpis.forEach((k, i) => {
      const x = PAGE.margin + i * (w + gap);
      doc.roundedRect(x, ky, w, 62, 4).lineWidth(0.8).stroke(BRAND.line);
      doc.rect(x, ky, w, 3).fill(k.alert ? BRAND.brick : BRAND.dark);
      doc.fillColor(k.alert ? BRAND.brick : BRAND.ink).font("Helvetica-Bold").fontSize(20)
        .text(String(k.value), x + 10, ky + 13, { width: w - 20, lineBreak: false, ellipsis: true });
      doc.fillColor(BRAND.muted).font("Helvetica").fontSize(8).text(k.label, x + 10, ky + 40, { width: w - 20 });
    });
    doc.y = ky + 62 + 14;
    doc.x = PAGE.margin;
  }
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
    ["Date de signature", fmtDate(signingTime)],
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
