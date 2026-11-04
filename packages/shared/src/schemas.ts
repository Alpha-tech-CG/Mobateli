import { z } from "zod";
import { ROLES, SEVERITIES, AGENT_PERMISSIONS, AGENT_DECISIONS } from "./enums.js";

/**
 * Zod schemas for API input validation. These are the single source of truth
 * for request shapes — the API validates every input against them (cahier §13.4).
 */

export const emailSchema = z.string().email().max(320);

/**
 * Password policy: min 12 chars. We do not cap length aggressively (argon2
 * handles long inputs), but bound it to avoid abuse.
 */
export const passwordSchema = z
  .string()
  .min(12, "Le mot de passe doit faire au moins 12 caractères")
  .max(256);

export const signupSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  name: z.string().min(1).max(120),
  organizationName: z.string().min(1).max(120),
});
export type SignupInput = z.infer<typeof signupSchema>;

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(256),
  /** 6-digit TOTP code, required only when MFA is enabled on the account. */
  totp: z
    .string()
    .regex(/^\d{6}$/, "Code à 6 chiffres attendu")
    .optional(),
});
export type LoginInput = z.infer<typeof loginSchema>;

export const mfaVerifySchema = z.object({
  totp: z.string().regex(/^\d{6}$/, "Code à 6 chiffres attendu"),
});
export type MfaVerifyInput = z.infer<typeof mfaVerifySchema>;

export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1).max(256),
    newPassword: passwordSchema,
  })
  .refine((v) => v.currentPassword !== v.newPassword, {
    message: "Le nouveau mot de passe doit être différent de l'actuel",
    path: ["newPassword"],
  });
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;

export const inviteMemberSchema = z.object({
  email: emailSchema,
  role: z.enum(ROLES),
});
export type InviteMemberInput = z.infer<typeof inviteMemberSchema>;

export const createPolicySchema = z.object({
  repositoryId: z.string().uuid().nullable().optional(),
  rule: z.string().min(1).max(120),
  action: z.enum(["allow", "warn", "block", "require_approval"]),
  severityThreshold: z.enum(SEVERITIES),
});
export type CreatePolicyInput = z.infer<typeof createPolicySchema>;

export const setAgentPolicySchema = z.object({
  permission: z.enum(AGENT_PERMISSIONS),
  decision: z.enum(AGENT_DECISIONS),
  allowlist: z.array(z.string().min(1).max(200)).max(200).default([]),
});
export type SetAgentPolicyInput = z.infer<typeof setAgentPolicySchema>;

export const guardActionSchema = z.object({
  repositoryId: z.string().uuid(),
  permission: z.enum(AGENT_PERMISSIONS),
  /** The package name, domain, command or path the agent wants to act on. */
  target: z.string().max(500).optional(),
  agentId: z.string().max(120).optional(),
});
export type GuardActionInput = z.infer<typeof guardActionSchema>;

export const auditQuerySchema = z.object({
  repositoryId: z.string().uuid().optional(),
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
  action: z.string().max(80).optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100),
});
export type AuditQueryInput = z.infer<typeof auditQuerySchema>;

export const auditExportSchema = z.object({
  format: z.enum(["json", "csv", "pdf"]).default("json"),
  repositoryId: z.string().uuid().optional(),
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
  severityThreshold: z.enum(SEVERITIES).optional(),
});
export type AuditExportInput = z.infer<typeof auditExportSchema>;

export const connectLinearSchema = z.object({
  apiKey: z.string().min(10).max(200),
  teamId: z.string().min(1).max(100),
});
export type ConnectLinearInput = z.infer<typeof connectLinearSchema>;

/**
 * The server POSTs to these URLs, so they are pinned to the real providers
 * over HTTPS — an arbitrary URL would let a user aim the API at internal
 * services (SSRF).
 */
export const connectSlackSchema = z.object({
  webhookUrl: z
    .string()
    .url()
    .max(500)
    .refine(
      (u) => u.startsWith("https://hooks.slack.com/"),
      "URL de webhook Slack attendue (https://hooks.slack.com/…)",
    ),
});
export type ConnectSlackInput = z.infer<typeof connectSlackSchema>;

export const connectSamlSchema = z.object({
  idpEntityId: z.string().min(1).max(300),
  idpSsoUrl: z.string().url().max(500),
  /** IdP signing certificate (PEM body, base64) used to verify assertions. */
  idpCert: z.string().min(50).max(10000),
});
export type ConnectSamlInput = z.infer<typeof connectSamlSchema>;

export const connectJiraSchema = z.object({
  baseUrl: z
    .string()
    .url()
    .max(300)
    .refine(
      (u) => /^https:\/\/[a-z0-9-]+\.atlassian\.net(\/.*)?$/i.test(u),
      "URL Jira Cloud attendue (https://<site>.atlassian.net)",
    ),
  email: emailSchema,
  apiToken: z.string().min(10).max(500),
  projectKey: z.string().min(1).max(50),
});
export type ConnectJiraInput = z.infer<typeof connectJiraSchema>;

/** Pagination shared across list endpoints. */
export const paginationSchema = z.object({
  cursor: z.string().uuid().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});
export type PaginationInput = z.infer<typeof paginationSchema>;
