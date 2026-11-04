// Server-side password reset for a locked-out user (no email reset flow yet).
// Sets a random temporary password, prints it ONCE on this terminal, and
// records the action in the audit trail. The user should then change it in
// "Mon compte".
//
// Usage (from the repository root, with DATABASE_URL in .env):
//   node --env-file=.env scripts/reset-password.mjs user@example.com
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const email = process.argv[2]?.trim().toLowerCase();
if (!email) {
  console.error("Usage: node --env-file=.env scripts/reset-password.mjs <email>");
  process.exit(1);
}

// Resolve the workspace's own packages (db client, argon2) from apps/api.
const require = createRequire(new URL("../apps/api/package.json", import.meta.url));
const { prisma } = await import(pathToFileURL(require.resolve("@codegate/db")).href);
const argon2 = require("argon2");

const user = await prisma.user.findFirst({ where: { email: { equals: email, mode: "insensitive" } } });
if (!user) {
  console.error(`Aucun compte pour ${email}.`);
  process.exit(1);
}

const tempPassword = randomBytes(18).toString("base64url");
await prisma.user.update({
  where: { id: user.id },
  data: { passwordHash: await argon2.hash(tempPassword, { type: argon2.argon2id }) },
});
await prisma.auditEvent.create({
  data: {
    organizationId: user.organizationId,
    actorType: "system",
    action: "member.password_reset",
    resourceType: "user",
    resourceId: user.id,
    metadata: { via: "cli" },
  },
});

console.log(`\nMot de passe temporaire pour ${user.email} (affiché une seule fois) :\n\n  ${tempPassword}\n`);
console.log("Connectez-vous avec, puis changez-le dans « Mon compte ».");
if (user.mfaEnabled) console.log("Attention : la MFA est active sur ce compte, le code TOTP reste exigé.");
await prisma.$disconnect();
