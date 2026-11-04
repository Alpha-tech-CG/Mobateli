import { z } from "zod";

/**
 * Environment is validated once at boot. A missing or malformed secret must
 * crash the process — a security product never starts in a half-configured
 * state (cahier §13.4).
 */
const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_PORT: z.coerce.number().int().positive().default(4000),

  DATABASE_URL: z.string().url(),
  REDIS_URL: z.string().url().default("redis://127.0.0.1:6380"),
  // "queue": BullMQ on Redis + separate worker process (VPS, local dev).
  // "inline": no Redis — analysis runs in the API process after the webhook is
  // acknowledged, and delivery idempotence lives in Postgres (serverless).
  ANALYSIS_MODE: z.enum(["queue", "inline"]).default("queue"),

  // ─── GitHub App ───────────────────────────────────────
  // Optional so the API boots in dev without a configured App. The webhook
  // route and installation auth refuse to operate until these are set.
  GITHUB_APP_ID: z.string().optional(),
  // PEM. In .env, newlines are written as literal "\n" and unescaped here.
  GITHUB_APP_PRIVATE_KEY: z
    .string()
    .optional()
    .transform((v) => v?.replace(/\\n/g, "\n")),
  GITHUB_WEBHOOK_SECRET: z.string().optional(),
  // Public slug of the App (github.com/apps/<slug>) for the install link.
  GITHUB_APP_SLUG: z.string().optional(),
  // Organization whose owner operates this deployment (defaults to the first one).
  PLATFORM_ORG_ID: z.string().uuid().optional(),
  // OAuth credentials of an env-configured App (the one-click App stores its
  // own). Used at "Connecter GitHub" to prove the user really has access to
  // the installation being linked.
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),

  // ─── Vercel ───────────────────────────────────────────
  VERCEL_WEBHOOK_SECRET: z.string().optional(),

  JWT_SECRET: z.string().min(32, "JWT_SECRET doit faire au moins 32 caractères"),
  // 32-byte key, base64-encoded, for AES-256-GCM at-rest encryption of secrets.
  ENCRYPTION_KEY: z
    .string()
    .refine(
      (v) => Buffer.from(v, "base64").length === 32,
      "ENCRYPTION_KEY doit être 32 octets encodés en base64",
    ),

  // Vercel Cron sends `Authorization: Bearer <CRON_SECRET>` to /api/v1/cron/*.
  CRON_SECRET: z.string().min(16).optional(),
  // Data minimisation (cahier §11.2): PR analyses and audit trail retention.
  RETENTION_DAYS: z.coerce.number().int().min(30).default(365),
  AUDIT_RETENTION_DAYS: z.coerce.number().int().min(365).default(730),

  // Global per-IP rate limit on every route (cahier §13.4).
  RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(10).default(100),

  // Owners/admins must enable MFA before administrative actions (§10.2).
  MFA_REQUIRED_FOR_ADMINS: z.enum(["true", "false"]).default("true"),

  // AI-written auditor's analysis in signed reports (Google Gemini). Only the
  // findings already in the report are sent — never code or secret values.
  GEMINI_API_KEY: z.string().optional(),
  GEMINI_MODEL: z.string().default("gemini-3.5-flash"),
  AI_NARRATIVE: z.enum(["on", "off"]).default("on"),

  // Optional trusted certificate (PKCS#12) for signing audit reports; without
  // it CodeGate generates and keeps its own signing identity.
  REPORT_SIGNING_P12_BASE64: z.string().optional(),
  REPORT_SIGNING_P12_PASSPHRASE: z.string().optional(),

  WEB_ORIGIN: z.string().url().default("http://localhost:3000"),
  // Transactional email (verification, password reset, invitations) via
  // Resend. Without a key, development logs the emails instead.
  RESEND_API_KEY: z.string().optional(),
  EMAIL_FROM: z.string().min(3).default("CodeGate <onboarding@resend.dev>"),
  // Public base URL of this API — used to build SAML SP entityId/ACS URLs.
  PUBLIC_API_URL: z.string().url().default("http://localhost:4000"),
});

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(): AppConfig {
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    // Flatten but never print secret values — only the failing keys.
    const issues = parsed.error.issues
      .map((i) => `  - ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new Error(`Configuration invalide :\n${issues}`);
  }
  return parsed.data;
}
