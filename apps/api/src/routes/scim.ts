import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { createHash, randomBytes } from "node:crypto";
import { prisma } from "@codegate/db";
import { hashPassword } from "../lib/password.js";
import { recordAudit } from "../lib/audit.js";

/**
 * SCIM 2.0 provisioning (cahier §12.2 P3). An IdP (Okta, Entra ID…) pushes
 * user lifecycle here with a bearer token. The token is stored hashed and
 * resolves the organization.
 */

declare module "fastify" {
  interface FastifyRequest {
    scimOrgId?: string;
  }
}

const USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";

interface ScimUser {
  id: string;
  email: string;
  name: string;
  active: boolean;
  createdAt: Date;
}

function toScimUser(u: ScimUser) {
  return {
    schemas: [USER_SCHEMA],
    id: u.id,
    userName: u.email,
    name: { formatted: u.name },
    displayName: u.name,
    emails: [{ value: u.email, primary: true }],
    active: u.active,
    meta: { resourceType: "User", created: u.createdAt.toISOString() },
  };
}

function scimError(reply: FastifyReply, status: number, detail: string) {
  return reply
    .code(status)
    .header("content-type", "application/scim+json")
    .send({ schemas: [ERROR_SCHEMA], status: String(status), detail });
}

export async function scimRoutes(app: FastifyInstance) {
  // Bearer-token auth that resolves the org by token hash.
  async function scimAuth(req: FastifyRequest, reply: FastifyReply) {
    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
    if (!token) return scimError(reply, 401, "Missing bearer token");
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const row = await prisma.scimToken.findUnique({
      where: { tokenHash },
      select: { organizationId: true },
    });
    if (!row) return scimError(reply, 401, "Invalid token");
    req.scimOrgId = row.organizationId;
  }

  const opts = { preHandler: [scimAuth] };

  // Create (provision) a user.
  app.post("/scim/v2/Users", opts, async (req, reply) => {
    const body = req.body as {
      userName?: string;
      displayName?: string;
      name?: { formatted?: string; givenName?: string; familyName?: string };
      active?: boolean;
    };
    const email = body.userName?.toLowerCase().trim();
    if (!email) return scimError(reply, 400, "userName is required");

    const name =
      body.displayName ??
      body.name?.formatted ??
      [body.name?.givenName, body.name?.familyName].filter(Boolean).join(" ") ??
      email.split("@")[0]!;

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      // Idempotent provisioning: 409 per SCIM when the user already exists.
      return scimError(reply, 409, "User already exists");
    }

    const user = await prisma.user.create({
      data: {
        organizationId: req.scimOrgId!,
        email,
        name,
        passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
        role: "developer",
        active: body.active ?? true,
      },
    });
    await recordAudit({
      organizationId: req.scimOrgId!,
      actorType: "system",
      action: "scim.user_provisioned",
      resourceType: "user",
      resourceId: user.id,
      metadata: { email },
    });
    return reply.code(201).header("content-type", "application/scim+json").send(toScimUser(user));
  });

  // List / filter (supports `filter=userName eq "x"`).
  app.get("/scim/v2/Users", opts, async (req, reply) => {
    const { filter } = req.query as { filter?: string };
    const where: { organizationId: string; email?: string } = {
      organizationId: req.scimOrgId!,
    };
    const m = filter?.match(/userName eq "([^"]+)"/i);
    if (m) where.email = m[1]!.toLowerCase();

    const users = await prisma.user.findMany({ where, orderBy: { createdAt: "asc" } });
    return reply.header("content-type", "application/scim+json").send({
      schemas: [LIST_SCHEMA],
      totalResults: users.length,
      startIndex: 1,
      itemsPerPage: users.length,
      Resources: users.map(toScimUser),
    });
  });

  app.get("/scim/v2/Users/:id", opts, async (req, reply) => {
    const { id } = req.params as { id: string };
    const user = await prisma.user.findFirst({ where: { id, organizationId: req.scimOrgId! } });
    if (!user) return scimError(reply, 404, "User not found");
    return reply.header("content-type", "application/scim+json").send(toScimUser(user));
  });

  // PATCH — we support the `active` attribute (de/reactivation).
  app.patch("/scim/v2/Users/:id", opts, async (req, reply) => {
    const { id } = req.params as { id: string };
    const user = await prisma.user.findFirst({ where: { id, organizationId: req.scimOrgId! } });
    if (!user) return scimError(reply, 404, "User not found");

    const body = req.body as { Operations?: { op: string; path?: string; value?: unknown }[] };
    let active = user.active;
    for (const op of body.Operations ?? []) {
      if (op.op.toLowerCase() !== "replace") continue;
      if (op.path === "active") active = Boolean(op.value);
      else if (op.value && typeof op.value === "object" && "active" in op.value) {
        active = Boolean((op.value as { active: unknown }).active);
      }
    }

    const updated = await prisma.user.update({ where: { id }, data: { active } });
    await recordAudit({
      organizationId: req.scimOrgId!,
      actorType: "system",
      action: active ? "scim.user_reactivated" : "scim.user_deactivated",
      resourceType: "user",
      resourceId: id,
    });
    return reply.header("content-type", "application/scim+json").send(toScimUser(updated));
  });

  // DELETE — soft-deactivate (preserve audit trail).
  app.delete("/scim/v2/Users/:id", opts, async (req, reply) => {
    const { id } = req.params as { id: string };
    const user = await prisma.user.findFirst({ where: { id, organizationId: req.scimOrgId! } });
    if (!user) return scimError(reply, 404, "User not found");
    await prisma.user.update({ where: { id }, data: { active: false } });
    await recordAudit({
      organizationId: req.scimOrgId!,
      actorType: "system",
      action: "scim.user_deactivated",
      resourceType: "user",
      resourceId: id,
    });
    return reply.code(204).send();
  });
}
