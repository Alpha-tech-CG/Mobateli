import type { FastifyInstance } from "fastify";
import { authenticator } from "otplib";
import { prisma } from "@codegate/db";
import {
  acceptInviteSchema,
  changePasswordSchema,
  forgotPasswordSchema,
  loginSchema,
  mfaVerifySchema,
  resetPasswordSchema,
  signupSchema,
  verifyEmailSchema,
} from "@codegate/shared";
import type { FastifyReply } from "fastify";
import { consumeToken, issueToken } from "../lib/auth-tokens.js";
import { sendEmail } from "../lib/mailer.js";
import {
  passwordChangedMessage,
  resetPasswordMessage,
  verifyEmailMessage,
} from "../lib/email-templates.js";
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

const INVALID_LINK = {
  error: "invalid_or_expired_token",
  message: "Ce lien est invalide, déjà utilisé ou expiré.",
} as const;

/** Second precision, so a login right after a reset is not caught by it. */
const revokeNow = () => new Date(Math.floor(Date.now() / 1000) * 1000);

export async function authRoutes(app: FastifyInstance, config: AppConfig) {
  // The token travels in the URL fragment: never sent to a server, never in
  // access logs or Referer headers.
  const link = (path: string, token: string) => `${config.WEB_ORIGIN}${path}#token=${token}`;

  async function sendVerification(user: { id: string; email: string; name: string }) {
    const token = await issueToken(user.id, "verify_email");
    return sendEmail(config, verifyEmailMessage(user.email, user.name, link("/verify-email", token)));
  }

  async function notifyPasswordChanged(user: { email: string; name: string }) {
    await sendEmail(config, passwordChangedMessage(user.email, user.name, `${config.WEB_ORIGIN}/forgot-password`)).catch(
      () => undefined,
    );
  }

  /** Throttle a token-submitting endpoint per IP; returns true when refused. */
  async function tokenThrottled(ip: string, reply: FastifyReply): Promise<boolean> {
    const ipKey = throttleKey("token:ip", ip);
    const retry = await lockedFor([ipKey]);
    if (retry) {
      await reply.code(429).header("retry-after", retry).send(tooManyAttempts(retry));
      return true;
    }
    await registerFailure(ipKey, RULES.tokenIp);
    return false;
  }
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
            termsAcceptedAt: new Date(),
            termsVersion: body.termsVersion ?? "unspecified",
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

    // Never fail the signup because the mail provider hiccuped: the user can
    // ask for a new link from the app.
    const mail = await sendVerification(user).catch(() => ({ sent: false }));

    const token = app.jwt.sign({
      userId: user.id,
      organizationId: org.id,
      role: "owner",
      mfa: false,
    });
    return reply.code(201).send({ token, mfaRequired: false, emailVerified: false, verificationSent: mail.sent });
  });

  /** The signed-in user (profile + account state for the app shell). */
  app.get("/api/v1/me", { preHandler: [app.authenticate] }, async (req) => {
    const user = await prisma.user.findUniqueOrThrow({
      where: { id: req.principal.userId },
      select: { id: true, email: true, name: true, role: true, mfaEnabled: true, emailVerifiedAt: true, organizationId: true },
    });
    const { emailVerifiedAt, ...rest } = user;
    return { user: { ...rest, emailVerified: emailVerifiedAt !== null } };
  });

  /** Confirm the email address from the link sent at signup. */
  app.post("/api/v1/auth/verify-email", async (req, reply) => {
    if (await tokenThrottled(req.ip, reply)) return;
    const body = verifyEmailSchema.parse(req.body);
    const userId = await consumeToken(body.token, "verify_email");
    if (!userId) return reply.code(400).send(INVALID_LINK);
    const user = await prisma.user.update({
      where: { id: userId },
      data: { emailVerifiedAt: new Date() },
      select: { id: true, organizationId: true },
    });
    await recordAudit({
      organizationId: user.organizationId,
      actorType: "user",
      actorId: user.id,
      action: "auth.email_verified",
      resourceType: "user",
      resourceId: user.id,
    });
    return { verified: true };
  });

  /** Send a fresh verification link to the signed-in user. */
  app.post("/api/v1/auth/verify-email/resend", { preHandler: [app.authenticate] }, async (req, reply) => {
    const user = await prisma.user.findUniqueOrThrow({
      where: { id: req.principal.userId },
      select: { id: true, email: true, name: true, emailVerifiedAt: true },
    });
    if (user.emailVerifiedAt) return { alreadyVerified: true, sent: false };
    const key = throttleKey("email:acct", user.id);
    const retry = await lockedFor([key]);
    if (retry) return reply.code(429).header("retry-after", retry).send(tooManyAttempts(retry));
    await registerFailure(key, RULES.emailAccount);
    const mail = await sendVerification(user);
    return { alreadyVerified: false, sent: mail.sent };
  });

  /**
   * Self-service password reset, step 1. Always answers the same way whether
   * or not the address has an account (no enumeration).
   */
  app.post("/api/v1/auth/forgot-password", async (req, reply) => {
    const body = forgotPasswordSchema.parse(req.body);
    const ipKey = throttleKey("email:ip", req.ip);
    const accountKey = throttleKey("email:reset", body.email);
    const ipRetry = await lockedFor([ipKey]);
    if (ipRetry) return reply.code(429).header("retry-after", ipRetry).send(tooManyAttempts(ipRetry));
    await registerFailure(ipKey, RULES.emailIp);
    // Per-address cap: silently stop sending, same answer (no mailbox flooding).
    const accountLocked = (await lockedFor([accountKey])) > 0;
    if (!accountLocked) {
      await registerFailure(accountKey, RULES.emailAccount);
      const user = await prisma.user.findUnique({
        where: { email: body.email },
        select: { id: true, email: true, name: true, active: true, organizationId: true },
      });
      if (user?.active) {
        const token = await issueToken(user.id, "reset_password");
        await sendEmail(config, resetPasswordMessage(user.email, user.name, link("/reset-password", token)));
        await recordAudit({
          organizationId: user.organizationId,
          actorType: "user",
          actorId: user.id,
          action: "auth.password_reset_requested",
          resourceType: "user",
          resourceId: user.id,
        });
      }
    }
    return reply.code(202).send({ ok: true });
  });

  /** Self-service password reset, step 2: the link + a new password. */
  app.post("/api/v1/auth/reset-password", async (req, reply) => {
    if (await tokenThrottled(req.ip, reply)) return;
    const body = resetPasswordSchema.parse(req.body);
    const userId = await consumeToken(body.token, "reset_password");
    if (!userId) return reply.code(400).send(INVALID_LINK);
    const current = await prisma.user.findUniqueOrThrow({ where: { id: userId }, select: { emailVerifiedAt: true } });
    const user = await prisma.user.update({
      where: { id: userId },
      data: {
        passwordHash: await hashPassword(body.password),
        // Every existing session is logged out (the account may be compromised).
        sessionsRevokedAt: revokeNow(),
        // Following the link proves control of the mailbox.
        emailVerifiedAt: current.emailVerifiedAt ?? new Date(),
      },
      select: { id: true, email: true, name: true, organizationId: true },
    });
    await clearThrottle(throttleKey("login:acct", user.email));
    await recordAudit({
      organizationId: user.organizationId,
      actorType: "user",
      actorId: user.id,
      action: "auth.password_reset",
      resourceType: "user",
      resourceId: user.id,
    });
    await notifyPasswordChanged(user);
    return { reset: true };
  });

  /** Activate an invited account: choose a password, get a session. */
  app.post("/api/v1/auth/accept-invite", async (req, reply) => {
    if (await tokenThrottled(req.ip, reply)) return;
    const body = acceptInviteSchema.parse(req.body);
    const userId = await consumeToken(body.token, "invite");
    if (!userId) return reply.code(400).send(INVALID_LINK);
    const existing = await prisma.user.findUniqueOrThrow({ where: { id: userId }, select: { active: true } });
    if (!existing.active) return reply.code(403).send({ error: "account_disabled" });
    const user = await prisma.user.update({
      where: { id: userId },
      data: {
        passwordHash: await hashPassword(body.password),
        emailVerifiedAt: new Date(),
        ...(body.name ? { name: body.name } : {}),
      },
      select: { id: true, organizationId: true, role: true },
    });
    await recordAudit({
      organizationId: user.organizationId,
      actorType: "user",
      actorId: user.id,
      action: "member.invite_accepted",
      resourceType: "user",
      resourceId: user.id,
    });
    const token = app.jwt.sign({ userId: user.id, organizationId: user.organizationId, role: user.role, mfa: false });
    return { token, mfaRequired: false };
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
      mfa: user.mfaEnabled,
    });
    return reply.send({ token, mfaRequired: false });
  });

  /**
   * Change one's own password. The current password is required, so a stolen
   * session alone can't lock the owner out of their account.
   */
  app.post(
    "/api/v1/auth/password",
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const body = changePasswordSchema.parse(req.body);
      const user = await prisma.user.findUniqueOrThrow({
        where: { id: req.principal.userId },
      });
      if (!(await verifyPassword(user.passwordHash, body.currentPassword))) {
        return reply.code(401).send({ error: "invalid_credentials" });
      }
      await prisma.user.update({
        where: { id: user.id },
        data: { passwordHash: await hashPassword(body.newPassword) },
      });
      await recordAudit({
        organizationId: user.organizationId,
        actorType: "user",
        actorId: user.id,
        action: "auth.password_changed",
        resourceType: "user",
        resourceId: user.id,
      });
      await notifyPasswordChanged(user);
      return { changed: true };
    },
  );

  /**
   * Begin MFA enrollment: generate a TOTP secret, store it encrypted (not yet
   * enabled), and return the otpauth URL for the authenticator app.
   */
  app.post(
    "/api/v1/auth/mfa/setup",
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      // Once MFA is on, re-running setup would silently swap the second
      // factor — a stolen session could take over the account's MFA.
      const current = await prisma.user.findUniqueOrThrow({
        where: { id: req.principal.userId },
        select: { mfaEnabled: true },
      });
      if (current.mfaEnabled) {
        return reply.code(409).send({ error: "mfa_already_enabled" });
      }
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
      // Fresh session carrying the second factor, so admin actions unlock now.
      const token = app.jwt.sign({
        userId: user.id,
        organizationId: user.organizationId,
        role: user.role,
        mfa: true,
      });
      return { mfaEnabled: true, token };
    },
  );
}
