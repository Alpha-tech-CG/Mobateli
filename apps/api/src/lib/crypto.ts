import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * AES-256-GCM encryption for secrets at rest (TOTP secrets, integration
 * tokens). cahier §10.3 — no secret is ever stored in clear text.
 *
 * Wire format (base64): [12B iv][16B auth tag][ciphertext].
 */
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

function key(encryptionKey: string): Buffer {
  return Buffer.from(encryptionKey, "base64");
}

export function encrypt(plaintext: string, encryptionKey: string): string {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", key(encryptionKey), iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

export function decrypt(payload: string, encryptionKey: string): string {
  const buf = Buffer.from(payload, "base64");
  const iv = buf.subarray(0, IV_LENGTH);
  const tag = buf.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const enc = buf.subarray(IV_LENGTH + TAG_LENGTH);
  const decipher = createDecipheriv("aes-256-gcm", key(encryptionKey), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
}
