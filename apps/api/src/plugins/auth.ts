import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import fastifyJwt from "@fastify/jwt";
import fp from "fastify-plugin";
import { prisma } from "@codegate/db";
import type { Role } from "@codegate/shared";

/** JWT payload carried in the bearer token. */
export interface AuthPrincipal {
  userId: string;
  organizationId: string;
  role: Role;
  /** True when this session passed a second factor (TOTP or the SSO IdP). */
  mfa?: boolean;
}

/** Roles that must use MFA before any administrative action (cahier §10.2). */
const MFA_ROLES: ReadonlySet<Role> = new Set(["owner", "admin"]);
/** Sessions expire (cahier §10.2). */
export const SESSION_TTL = "12h";

declare module "fastify" {
  interface FastifyInstance {
    /** Pre-handler: rejects unauthenticated requests (cahier §13.4). */
    authenticate: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
    /** Pre-handler factory: requires one of the given roles. */
    requireRole: (
      ...roles: Role[]
    ) => (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
  interface FastifyRequest {
    principal: AuthPrincipal;
  }
}

declare module "@fastify/jwt" {
  interface FastifyJWT {
    payload: AuthPrincipal;
    user: AuthPrincipal;
  }
}

/** The account behind a session, as stored now (not as the token says). */
export interface SessionAccount {
  active: boolean;
  role: Role;
  organizationId: string;
}

const loadAccountFromDb = (p: AuthPrincipal): Promise<SessionAccount | null> =>
  prisma.user.findUnique({
    where: { id: p.userId },
    select: { active: true, role: true, organizationId: true },
  });

async function authPlugin(
  app: FastifyInstance,
  opts: {
    jwtSecret: string;
    mfaRequiredForAdmins: boolean;
    /** Account lookup (database by default; injectable for unit tests). */
    loadAccount?: (principal: AuthPrincipal) => Promise<SessionAccount | null>;
  },
) {
  await app.register(fastifyJwt, { secret: opts.jwtSecret, sign: { expiresIn: SESSION_TTL } });
  const loadAccount = opts.loadAccount ?? loadAccountFromDb;

  app.decorate("authenticate", async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      await req.jwtVerify();
    } catch {
      await reply.code(401).send({ error: "unauthorized" });
      return;
    }
    // Re-check the account on every request: a deprovisioned (SCIM) or
    // deactivated user is locked out immediately, and a role change takes
    // effect without waiting for the token to expire.
    const user = await loadAccount(req.user);
    if (!user || !user.active || user.organizationId !== req.user.organizationId) {
      await reply.code(401).send({ error: "unauthorized" });
      return;
    }
    req.principal = { ...req.user, role: user.role };
  });

  app.decorate("requireRole", (...roles: Role[]) => {
    return async (req: FastifyRequest, reply: FastifyReply) => {
      if (!req.principal) {
        await reply.code(401).send({ error: "unauthorized" });
        return;
      }
      if (!roles.includes(req.principal.role)) {
        await reply.code(403).send({ error: "forbidden" });
        return;
      }
      if (opts.mfaRequiredForAdmins && MFA_ROLES.has(req.principal.role) && !req.principal.mfa) {
        await reply.code(403).send({ error: "mfa_enrollment_required" });
      }
    };
  });
}

export default fp(authPlugin, { name: "auth" });
