import type { FastifyInstance } from "fastify";
import { randomBytes } from "node:crypto";
import { prisma } from "@codegate/db";
import { hashPassword } from "../lib/password.js";
import { recordAudit } from "../lib/audit.js";
import { buildSaml } from "../lib/saml.js";
import type { AppConfig } from "../config.js";

/**
 * SAML SP endpoints (cahier §12.2 P3). Public, per-organization:
 *   GET  /saml/:orgId/metadata  — SP metadata XML for the IdP
 *   GET  /saml/:orgId/login     — SP-initiated login (redirect to IdP)
 *   POST /saml/:orgId/acs       — assertion consumer → issues a CodeGate JWT
 */
export async function samlRoutes(app: FastifyInstance, config: AppConfig) {
  async function loadConn(orgId: string) {
    return prisma.samlConnection.findUnique({ where: { organizationId: orgId } });
  }

  app.get("/saml/:orgId/metadata", async (req, reply) => {
    const { orgId } = req.params as { orgId: string };
    const conn = await loadConn(orgId);
    if (!conn) return reply.code(404).send({ error: "saml_not_configured" });
    const saml = buildSaml(config, conn, orgId);
    const xml = saml.generateServiceProviderMetadata(null, null);
    return reply.header("content-type", "application/xml").send(xml);
  });

  app.get("/saml/:orgId/login", async (req, reply) => {
    const { orgId } = req.params as { orgId: string };
    const conn = await loadConn(orgId);
    if (!conn) return reply.code(404).send({ error: "saml_not_configured" });
    const saml = buildSaml(config, conn, orgId);
    const url = await saml.getAuthorizeUrlAsync("", undefined, {});
    return reply.redirect(url);
  });

  app.post("/saml/:orgId/acs", async (req, reply) => {
    const { orgId } = req.params as { orgId: string };
    const conn = await loadConn(orgId);
    if (!conn) return reply.code(404).send({ error: "saml_not_configured" });

    const body = req.body as { SAMLResponse?: string };
    if (!body?.SAMLResponse) return reply.code(400).send({ error: "missing_saml_response" });

    const saml = buildSaml(config, conn, orgId);
    let email: string | undefined;
    try {
      const { profile } = await saml.validatePostResponseAsync({ SAMLResponse: body.SAMLResponse });
      email = (profile?.email ?? profile?.nameID)?.toString().toLowerCase();
    } catch (err) {
      req.log.warn({ err }, "SAML assertion validation failed");
      return reply.code(401).send({ error: "invalid_assertion" });
    }
    if (!email) return reply.code(401).send({ error: "no_email_in_assertion" });

    // Just-in-time provisioning: link or create the user in this org.
    let user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      user = await prisma.user.create({
        data: {
          organizationId: orgId,
          email,
          name: email.split("@")[0]!,
          passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
          role: "developer",
        },
      });
    }
    if (user.organizationId !== orgId) {
      return reply.code(403).send({ error: "user_in_other_org" });
    }
    if (!user.active) return reply.code(403).send({ error: "account_disabled" });

    await recordAudit({
      organizationId: orgId,
      actorType: "user",
      actorId: user.id,
      action: "auth.saml_login",
      resourceType: "user",
      resourceId: user.id,
    });

    const token = app.jwt.sign({
      userId: user.id,
      organizationId: user.organizationId,
      role: user.role,
      // Strong authentication is delegated to the IdP.
      mfa: true,
    });
    // An IdP posts here directly; return the token (a browser flow would
    // instead redirect to the web app with the token).
    return reply.send({ token });
  });
}
