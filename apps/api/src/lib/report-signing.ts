import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import forge from "node-forge";
import { prisma } from "@codegate/db";
import type { AppConfig } from "../config.js";
import { decrypt, encrypt } from "./crypto.js";

/**
 * Identity CodeGate signs its audit reports with (PAdES / PKCS#7 detached).
 *
 * By default the platform generates its own RSA-3072 key and X.509
 * certificate on first use and keeps them encrypted in platform_settings.
 * A certificate from a trusted authority (eIDAS / Adobe AATL) can replace it
 * with REPORT_SIGNING_P12_BASE64 + REPORT_SIGNING_P12_PASSPHRASE: PDF readers
 * then show the signer as trusted instead of "identity unknown".
 */
export interface SigningIdentity {
  p12: Buffer;
  passphrase: string;
  /** SHA-256 of the certificate (DER), uppercase hex pairs separated by ":". */
  fingerprint: string;
  subject: string;
  notAfter: string;
  source: "platform" | "env";
}

interface StoredIdentity {
  p12: string;
  passphrase: string;
  fingerprint: string;
  subject: string;
  notAfter: string;
}

const SETTING_KEY = "report_signing_identity";
const SUBJECT = [
  { name: "commonName", value: "CodeGate Audit Report Signing" },
  { name: "organizationName", value: "CodeGate" },
  { name: "organizationalUnitName", value: "Security Evidence" },
  { name: "countryName", value: "FR" },
];

function describe(p12: Buffer, passphrase: string) {
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(p12.toString("binary")));
  const parsed = forge.pkcs12.pkcs12FromAsn1(asn1, passphrase);
  const certBag = forge.pki.oids.certBag!;
  const bag = parsed.getBags({ bagType: certBag })[certBag]?.[0];
  if (!bag?.cert) throw new Error("report_signing_certificate_missing");
  const der = Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(bag.cert)).getBytes(), "binary");
  return {
    fingerprint: certificateFingerprint(der),
    subject: bag.cert.subject.attributes.map((a: forge.pki.CertificateField) => `${a.shortName}=${String(a.value)}`).join(", "),
    notAfter: bag.cert.validity.notAfter.toISOString(),
  };
}

export function certificateFingerprint(der: Buffer): string {
  return createHash("sha256").update(der).digest("hex").toUpperCase().match(/../g)!.join(":");
}

/** Self-signed signing certificate, valid 10 years. */
export function generateIdentity(): StoredIdentity {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 3072 });
  const key = forge.pki.privateKeyFromPem(privateKey.export({ type: "pkcs1", format: "pem" }).toString());
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(publicKey.export({ type: "spki", format: "pem" }).toString());
  cert.serialNumber = `01${randomBytes(15).toString("hex")}`;
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000);
  cert.setSubject(SUBJECT);
  cert.setIssuer(SUBJECT);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true, nonRepudiation: true },
    { name: "extKeyUsage", emailProtection: true },
    { name: "subjectKeyIdentifier" },
  ]);
  cert.sign(key, forge.md.sha256.create());

  const passphrase = randomBytes(24).toString("base64url");
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, [cert], passphrase, { algorithm: "aes256" });
  const p12 = Buffer.from(forge.asn1.toDer(p12Asn1).getBytes(), "binary");
  return { p12: p12.toString("base64"), passphrase, ...describe(p12, passphrase) };
}

let cached: SigningIdentity | null = null;

export async function getSigningIdentity(config: AppConfig): Promise<SigningIdentity> {
  if (cached) return cached;
  if (config.REPORT_SIGNING_P12_BASE64) {
    const p12 = Buffer.from(config.REPORT_SIGNING_P12_BASE64, "base64");
    const passphrase = config.REPORT_SIGNING_P12_PASSPHRASE ?? "";
    cached = { p12, passphrase, ...describe(p12, passphrase), source: "env" };
    return cached;
  }

  let row = await prisma.platformSetting.findUnique({ where: { key: SETTING_KEY } });
  if (!row) {
    const fresh = generateIdentity();
    try {
      row = await prisma.platformSetting.create({
        data: { key: SETTING_KEY, valueEncrypted: encrypt(JSON.stringify(fresh), config.ENCRYPTION_KEY) },
      });
    } catch {
      // Another instance created it first: keep a single identity.
      row = await prisma.platformSetting.findUniqueOrThrow({ where: { key: SETTING_KEY } });
    }
  }
  const stored = JSON.parse(decrypt(row.valueEncrypted, config.ENCRYPTION_KEY)) as StoredIdentity;
  cached = {
    p12: Buffer.from(stored.p12, "base64"),
    passphrase: stored.passphrase,
    fingerprint: stored.fingerprint,
    subject: stored.subject,
    notAfter: stored.notAfter,
    source: "platform",
  };
  return cached;
}

/** For tests: forget the in-memory identity. */
export function resetSigningIdentityCache(): void {
  cached = null;
}
