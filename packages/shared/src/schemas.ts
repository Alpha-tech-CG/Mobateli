import { z } from "zod";
import { ROLES, SEVERITIES } from "./enums.js";

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

/** Pagination shared across list endpoints. */
export const paginationSchema = z.object({
  cursor: z.string().uuid().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});
export type PaginationInput = z.infer<typeof paginationSchema>;
