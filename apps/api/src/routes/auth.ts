import type { FastifyInstance } from "fastify";
import { authenticator } from "otplib";
import { prisma } from "@codegate/db";
import {
  loginSchema,
  mfaVerifySchema,
  signupSchema,
} from "@codegate/shared";
import { hashPassword, verifyPassword } from "../lib/password.js";
import { encrypt, decrypt } from "../lib/crypto.js";
import { recordAudit } from "../lib/audit.js";
import { notifySlack } from "../lib/notify.js";
import {
  RULES,
  clearThrottle,
  lockedFor,
  registerFailure,
  throttleKey,
  tooManyAttempts,
} from "../lib/throttle.js";
import type { AppConfig } from "../config.js";

// Verified against when the email is unknown, so a missing account costs the
// same argon2 time as a wrong password (no timing-based enumeration).
let dummyHash: Promise<string> | undefined;
const getDummyHash = () => (dummyHash ??= hashPassword("codegate-timing-equalizer"));

const INVALID_CREDENTIALS = {
  error: "invalid_credentials",
  message: "Email ou mot de passe incorrect.",
} as const;

export async function authRoutes(app: FastifyInstance, config: AppConfig) {
  /** Audit + Slack when an account gets locked (alert_after, §4.3). */
  async function reportLockout(organizationId: string, userId: string, factor: "password" | "totp") {
    await recordAudit({
      organizationId,
      actorType: "system",
      action: "auth.lockout",
      resourceType: "user",
      resourceId: userId,
      metadata: { factor },
    });
    await notifySlack(organizationId, config.ENCRYPTION_KEY, {
      title: "Compte verrouillé après des tentatives répétées",
      severity: "warning",
      repository: "Authentification CodeGate",
      detail: `Un compte de l'organisation a été verrouillé temporairement (échecs ${
        factor === "totp" ? "de code MFA" : "de mot de passe"
      }). Vérifiez le journal d'audit.`,
    });
  }

  /**
   * Signup bootstraps an organization and its first user as `owner`.
   */
  app.post("/api/v1/auth/signup", async (req, reply) => {
    // 5 signups per IP per hour (extension §4.4), counted before validation.
    const ipKey = throttleKey("signup:ip", req.ip);
    const retry = await lockedFor([ipKey]);
    if (retry) return reply.code(429).header("retry-after", retry).send(tooManyAttempts(retry));
    await registerFailure(ipKey, RULES.signupIp);

    const body = signupSchema.parse(req.body);

    const existing = await prisma.user.findUnique({ where: { email: body.email } });
    if (existing) {
      // Do not leak which emails exist beyond the unavoidable 409.
      return reply.code(409).send({ error: "email_taken" });
    }

    const passwordHash = await hashPassword(body.password);

    const org = await prisma.organization.create({
      data: {
        name: body.organizationName,
        users: {
          create: {
            email: body.email,
            name: body.name,
            passwordHash,
            role: "owner",
          },
        },
      },
      include: { users: true },
    });
    const user = org.users[0]!;

    await recordAudit({
      organizationId: org.id,
      actorType: "user",
      actorId: user.id,
      action: "org.created",
      resourceType: "organization",
      resourceId: org.id,
    });

    const token = app.jwt.sign({
      userId: user.id,
      organizationId: org.id,
      role: "owner",
    });
    return reply.code(201).send({ token, mfaRequired: false });
  });

  /**
   * Login. When MFA is enabled, a valid 6-digit TOTP is mandatory.
   */
  app.post("/api/v1/auth/login", async (req, reply) => {
    const body = loginSchema.parse(req.body);

    // Locked by account or by IP → refuse before touching the password.
    const accountKey = throttleKey("login:acct", body.email);
    const ipKey = throttleKey("login:ip", req.ip);
    const retry = await lockedFor([accountKey, ipKey]);
    if (retry) return reply.code(429).header("retry-after", retry).send(tooManyAttempts(retry));

    const user = await prisma.user.findUnique({ where: { email: body.email } });
    const passwordOk = user
      ? await verifyPassword(user.passwordHash, body.password)
      : (await verifyPassword(await getDummyHash(), body.password), false);

    if (!user || !passwordOk) {
      const [accountLocked] = await Promise.all([
        registerFailure(accountKey, RULES.loginAccount),
        registerFailure(ipKey, RULES.loginIp),
      ]);
      if (accountLocked && user) await reportLockout(user.organizationId, user.id, "password");
      return reply.code(401).send(INVALID_CREDENTIALS);
    }
    // Deprovisioned (SCIM-deactivated) users cannot sign in.
    if (!user.active) {
      return reply.code(403).send({ error: "account_disabled" });
    }

    if (user.mfaEnabled) {
      if (!body.totp) {
        return reply.code(401).send({ error: "mfa_required", mfaRequired: true });
      }
      const totpKey = throttleKey("totp:acct", user.id);
      const totpRetry = await lockedFor([totpKey]);
      if (totpRetry) {
        return reply.code(429).header("retry-after", totpRetry).send(tooManyAttempts(totpRetry));
      }
      const secret = decrypt(user.mfaSecret!, config.ENCRYPTION_KEY);
      if (!authenticator.verify({ token: body.totp, secret })) {
        if (await registerFailure(totpKey, RULES.totpAccount)) {
          await reportLockout(user.organizationId, user.id, "totp");
        }
        return reply.code(401).send({ error: "invalid_totp" });
      }
      await clearThrottle(totpKey);
    }
    await clearThrottle(accountKey);

    await recordAudit({
      organizationId: user.organizationId,
      actorType: "user",
      actorId: user.id,
      action: "auth.login",
      resourceType: "user",
      resourceId: user.id,
    });

    const token = app.jwt.sign({
      userId: user.id,
      organizationId: user.organizationId,
      role: user.role,
    });
    return reply.send({ token, mfaRequired: false });
  });

  /**
   * Begin MFA enrollment: generate a TOTP secret, store it encrypted (not yet
   * enabled), and return the otpauth URL for the authenticator app.
   */
  app.post(
    "/api/v1/auth/mfa/setup",
    { preHandler: [app.authenticate] },
    async (req) => {
      const secret = authenticator.generateSecret();
      await prisma.user.update({
        where: { id: req.principal.userId },
        data: { mfaSecret: encrypt(secret, config.ENCRYPTION_KEY) },
      });
      const user = await prisma.user.findUniqueOrThrow({
        where: { id: req.principal.userId },
      });
      const otpauth = authenticator.keyuri(user.email, "CodeGate", secret);
      return { otpauth };
    },
  );

  /**
   * Confirm the first TOTP code and flip MFA on.
   */
  app.post(
    "/api/v1/auth/mfa/verify",
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const body = mfaVerifySchema.parse(req.body);
      const user = await prisma.user.findUniqueOrThrow({
        where: { id: req.principal.userId },
      });
      if (!user.mfaSecret) {
        return reply.code(400).send({ error: "mfa_not_initialized" });
      }
      const totpKey = throttleKey("totp:acct", user.id);
      const retry = await lockedFor([totpKey]);
      if (retry) return reply.code(429).header("retry-after", retry).send(tooManyAttempts(retry));
      const secret = decrypt(user.mfaSecret, config.ENCRYPTION_KEY);
      if (!authenticator.verify({ token: body.totp, secret })) {
        await registerFailure(totpKey, RULES.totpAccount);
        return reply.code(401).send({ error: "invalid_totp" });
      }
      await clearThrottle(totpKey);
      await prisma.user.update({
        where: { id: user.id },
        data: { mfaEnabled: true },
      });
      await recordAudit({
        organizationId: user.organizationId,
        actorType: "user",
        actorId: user.id,
        action: "auth.mfa_enabled",
        resourceType: "user",
        resourceId: user.id,
      });
      return { mfaEnabled: true };
    },
  );
}
