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
import type { AppConfig } from "../config.js";

export async function authRoutes(app: FastifyInstance, config: AppConfig) {
  /**
   * Signup bootstraps an organization and its first user as `owner`.
   */
  app.post("/api/v1/auth/signup", async (req, reply) => {
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

    const user = await prisma.user.findUnique({ where: { email: body.email } });
    // Constant-ish response regardless of whether the user exists.
    if (!user || !(await verifyPassword(user.passwordHash, body.password))) {
      return reply.code(401).send({ error: "invalid_credentials" });
    }

    if (user.mfaEnabled) {
      if (!body.totp) {
        return reply.code(401).send({ error: "mfa_required", mfaRequired: true });
      }
      const secret = decrypt(user.mfaSecret!, config.ENCRYPTION_KEY);
      if (!authenticator.verify({ token: body.totp, secret })) {
        return reply.code(401).send({ error: "invalid_totp" });
      }
    }

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
      const secret = decrypt(user.mfaSecret, config.ENCRYPTION_KEY);
      if (!authenticator.verify({ token: body.totp, secret })) {
        return reply.code(401).send({ error: "invalid_totp" });
      }
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
