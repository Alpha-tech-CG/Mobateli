import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { decrypt, encrypt } from "./crypto.js";

const KEY = randomBytes(32).toString("base64");

test("crypto: round trip", () => {
  assert.equal(decrypt(encrypt("totp-secret", KEY), KEY), "totp-secret");
});

test("crypto: tampered ciphertext is rejected", () => {
  const buf = Buffer.from(encrypt("totp-secret", KEY), "base64");
  buf[buf.length - 1]! ^= 0xff;
  assert.throws(() => decrypt(buf.toString("base64"), KEY));
});

test("crypto: truncated payload (short auth tag) is rejected", () => {
  const buf = Buffer.from(encrypt("", KEY), "base64"); // iv + tag, empty ciphertext
  for (const len of [0, 12, 16, 20, 27]) {
    assert.throws(() => decrypt(buf.subarray(0, len).toString("base64"), KEY), `length ${len}`);
  }
});
