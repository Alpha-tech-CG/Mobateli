import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";
import { inviteMemberSchema, updateMemberSchema } from "@codegate/shared";
import { hashPassword } from "../lib/password.js";
import { recordAudit } from "../lib/audit.js";
import { randomBytes } from "node:crypto";
import type { AppConfig } from "../config.js";
import { issueToken } from "../lib/auth-tokens.js";
import { mailConfigured, sendEmail } from "../lib/mailer.js";
import { inviteMessage } from "../lib/email-templates.js";

export async function organizationRoutes(app: FastifyInstance, config: AppConfig) {
  /** Current organization (scoped to the principal's org). */
  app.get(
    "/api/v1/organization",
    { preHandler: [app.authenticate] },
    async (req) => {
      const org = await prisma.organization.findUniqueOrThrow({
        where: { id: req.principal.organizationId },
        select: { id: true, name: true, plan: true, region: true, createdAt: true },
      });
      return org;
    },
  );

  /** List repositories connected to the current organization. */
  app.get(
    "/api/v1/repositories",
    { preHandler: [app.authenticate] },
    async (req) => {
      const repositories = await prisma.repository.findMany({
        where: { organizationId: req.principal.organizationId },
        select: {
          id: true,
          name: true,
          provider: true,
          defaultBranch: true,
          protectionLevel: true,
          autoScan: true,
          installationId: true,
          scans: {
            orderBy: { createdAt: "desc" },
            take: 1,
            select: { id: true, status: true, riskScore: true, finishedAt: true, createdAt: true },
          },
        },
        orderBy: { name: "asc" },
      });
      return {
        repositories: repositories.map(({ installationId, scans, ...r }) => ({
          ...r,
          // A GitHub repo is scannable only while the App is installed on it.
          scannable: r.provider !== "github" || installationId !== null,
          lastScan: scans[0] ?? null,
        })),
      };
    },
  );

  /** List recent deployment security checks (Deploy Gate, cahier §5.5). */
  app.get(
    "/api/v1/deploy-checks",
    { preHandler: [app.authenticate] },
    async (req) => {
      const checks = await prisma.deployCheck.findMany({
        where: { repository: { organizationId: req.principal.organizationId } },
        include: { repository: { select: { name: true } } },
        orderBy: { createdAt: "desc" },
        take: 100,
      });
      return {
        deployChecks: checks.map((c) => ({
          id: c.id,
          repository: c.repository.name,
          provider: c.provider,
          target: c.target,
          commitSha: c.commitSha,
          decision: c.decision,
          reason: c.reason,
          createdAt: c.createdAt,
        })),
      };
    },
  );

  /** List members of the current organization. */
  app.get(
    "/api/v1/organization/members",
    { preHandler: [app.authenticate] },
    async (req) => {
      const members = await prisma.user.findMany({
        where: { organizationId: req.principal.organizationId },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          mfaEnabled: true,
          active: true,
          createdAt: true,
        },
        orderBy: { createdAt: "asc" },
      });
      return { members };
    },
  );

  /**
   * Invite a member. MVP: creates the user with a random temporary password
   * (a real invite email flow comes later). Owner/admin only.
   */
  app.post(
    "/api/v1/organization/members",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req, reply) => {
      const body = inviteMemberSchema.parse(req.body);
      // Only an owner may grant owner — otherwise an admin could escalate.
      if (body.role === "owner" && req.principal.role !== "owner") {
        return reply.code(403).send({ error: "forbidden" });
      }

      const existing = await prisma.user.findUnique({ where: { email: body.email } });
      if (existing) {
        return reply.code(409).send({ error: "email_taken" });
      }

      const tempPassword = randomBytes(24).toString("base64url");
      const user = await prisma.user.create({
        data: {
          organizationId: req.principal.organizationId,
          email: body.email,
          name: body.email.split("@")[0]!,
          passwordHash: await hashPassword(tempPassword),
          role: body.role,
        },
        select: { id: true, email: true, role: true },
      });

      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "member.invited",
        resourceType: "user",
        resourceId: user.id,
        metadata: { role: body.role },
      });

      // With email configured, the invitee gets a one-time activation link
      // and chooses their own password; the random one above is never shown.
      if (mailConfigured(config)) {
        const [inviter, org] = await Promise.all([
          prisma.user.findUniqueOrThrow({ where: { id: req.principal.userId }, select: { name: true } }),
          prisma.organization.findUniqueOrThrow({ where: { id: req.principal.organizationId }, select: { name: true } }),
        ]);
        const token = await issueToken(user.id, "invite");
        const mail = await sendEmail(
          config,
          inviteMessage(user.email, inviter.name, org.name, body.role, `${config.WEB_ORIGIN}/invite#token=${token}`),
        );
        if (mail.sent) return reply.code(201).send({ user, inviteSent: true });
      }
      // No email provider (or it failed): tempPassword is returned once so the
      // inviter can relay it out-of-band; it is never persisted in clear text.
      return reply.code(201).send({ user, inviteSent: false, tempPassword });
    },
  );

  /**
   * Change a member's role or (de)activate them (cahier §12.1). Guard rails:
   * an admin never touches owners nor grants ownership, nobody locks
   * themselves out, and the organization always keeps an active owner.
   */
  app.patch(
    "/api/v1/organization/members/:id",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const body = updateMemberSchema.parse(req.body);
      const { organizationId, userId, role: actorRole } = req.principal;
      const member = await prisma.user.findFirst({ where: { id, organizationId } });
      if (!member) return reply.code(404).send({ error: "not_found" });
      if (id === userId) return reply.code(409).send({ error: "cannot_modify_self" });
      if (actorRole !== "owner" && (member.role === "owner" || body.role === "owner")) {
        return reply.code(403).send({ error: "owner_only" });
      }
      const losesOwner =
        member.role === "owner" && ((body.role && body.role !== "owner") || body.active === false);
      if (losesOwner) {
        const owners = await prisma.user.count({ where: { organizationId, role: "owner", active: true } });
        if (owners <= 1) return reply.code(409).send({ error: "last_owner" });
      }

      const updated = await prisma.user.update({
        where: { id },
        data: { ...(body.role ? { role: body.role } : {}), ...(body.active !== undefined ? { active: body.active } : {}) },
        select: { id: true, email: true, name: true, role: true, active: true },
      });
      await recordAudit({
        organizationId,
        actorType: "user",
        actorId: userId,
        action: body.active === false ? "member.deactivated" : body.active === true ? "member.reactivated" : "member.role_changed",
        resourceType: "user",
        resourceId: id,
        metadata: { from: member.role, to: updated.role, active: updated.active },
      });
      return { member: updated };
    },
  );

  /**
   * Reset a member's password (lost password, no email flow yet). Returns a
   * one-time temporary password to relay out-of-band. Owner/admin only; only
   * an owner may reset an owner.
   */
  app.post(
    "/api/v1/organization/members/:id/reset-password",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const member = await prisma.user.findFirst({
        where: { id, organizationId: req.principal.organizationId },
        select: { id: true, role: true },
      });
      if (!member) return reply.code(404).send({ error: "not_found" });
      if (member.role === "owner" && req.principal.role !== "owner") {
        return reply.code(403).send({ error: "forbidden" });
      }

      const tempPassword = randomBytes(24).toString("base64url");
      await prisma.user.update({
        where: { id: member.id },
        data: { passwordHash: await hashPassword(tempPassword) },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "member.password_reset",
        resourceType: "user",
        resourceId: member.id,
      });
      return { tempPassword };
    },
  );
}
