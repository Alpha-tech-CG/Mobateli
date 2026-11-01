import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import fastifyJwt from "@fastify/jwt";
import fp from "fastify-plugin";
import type { Role } from "@codegate/shared";

/** JWT payload carried in the bearer token. */
export interface AuthPrincipal {
  userId: string;
  organizationId: string;
  role: Role;
}

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

async function authPlugin(app: FastifyInstance, opts: { jwtSecret: string }) {
  await app.register(fastifyJwt, { secret: opts.jwtSecret });

  app.decorate("authenticate", async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      await req.jwtVerify();
      req.principal = req.user;
    } catch {
      await reply.code(401).send({ error: "unauthorized" });
    }
  });

  app.decorate("requireRole", (...roles: Role[]) => {
    return async (req: FastifyRequest, reply: FastifyReply) => {
      if (!req.principal) {
        await reply.code(401).send({ error: "unauthorized" });
        return;
      }
      if (!roles.includes(req.principal.role)) {
        await reply.code(403).send({ error: "forbidden" });
      }
    };
  });
}

export default fp(authPlugin, { name: "auth" });
