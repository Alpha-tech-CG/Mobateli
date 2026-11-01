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

  JWT_SECRET: z.string().min(32, "JWT_SECRET doit faire au moins 32 caractères"),
  // 32-byte key, base64-encoded, for AES-256-GCM at-rest encryption of secrets.
  ENCRYPTION_KEY: z
    .string()
    .refine(
      (v) => Buffer.from(v, "base64").length === 32,
      "ENCRYPTION_KEY doit être 32 octets encodés en base64",
    ),

  WEB_ORIGIN: z.string().url().default("http://localhost:3000"),
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
