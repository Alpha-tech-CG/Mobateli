import argon2 from "argon2";

/**
 * Password hashing with argon2id — memory-hard, the current OWASP default.
 */
export function hashPassword(plain: string): Promise<string> {
  return argon2.hash(plain, { type: argon2.argon2id });
}

export function verifyPassword(hash: string, plain: string): Promise<boolean> {
  return argon2.verify(hash, plain);
}
