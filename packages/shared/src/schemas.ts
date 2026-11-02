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

export const connectSlackSchema = z.object({
  webhookUrl: z.string().url().max(500),
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
  baseUrl: z.string().url().max(300),
  email: emailSchema,
  apiToken: z.string().min(10).max(500),
  projectKey: z.string().min(1).max(50),
});
export type ConnectJiraInput = z.infer<typeof connectJiraSchema>;

// ─── Infra Shield (extension §3) ──────────────────────────

export const connectServerSchema = z.object({
  name: z.string().min(1).max(100),
  provider: z.string().max(60).optional(),
  environment: z.enum(["production", "staging", "development"]).default("production"),
});
export type ConnectServerInput = z.infer<typeof connectServerSchema>;

/**
 * Facts collected by the read-only CodeGate agent on a server. `null` means
 * "could not be determined" (tool missing, not run as root) — never "safe".
 * The agent never sends file contents, secrets or environment variables.
 */
export const agentReportSchema = z.object({
  agentVersion: z.string().max(20),
  hostname: z.string().max(255),
  os: z.string().max(120).nullable(),
  listening: z
    .array(
      z.object({
        proto: z.enum(["tcp", "udp"]),
        address: z.string().max(64),
        port: z.number().int().min(0).max(65535),
        process: z.string().max(80).nullable(),
      }),
    )
    .max(2000),
  ssh: z.object({
    permitRootLogin: z.string().max(40).nullable(),
    passwordAuthentication: z.boolean().nullable(),
    pubkeyAuthentication: z.boolean().nullable(),
    maxAuthTries: z.number().int().nullable(),
  }).nullable(),
  firewall: z.object({
    ufw: z.enum(["active", "inactive"]).nullable(),
    nftablesRules: z.number().int().nullable(),
    iptablesRules: z.number().int().nullable(),
  }),
  bruteforce: z.object({
    fail2ban: z.boolean().nullable(),
    crowdsec: z.boolean().nullable(),
  }),
  docker: z
    .object({
      containers: z
        .array(
          z.object({
            name: z.string().max(255),
            image: z.string().max(500),
            user: z.string().max(100),
            privileged: z.boolean(),
            dockerSocketMounted: z.boolean(),
            capAdd: z.array(z.string().max(60)).max(60),
            publishedPorts: z
              .array(z.object({ hostIp: z.string().max(64), hostPort: z.number().int() }))
              .max(200),
            readOnlyRootfs: z.boolean(),
            memoryLimit: z.number().int().nonnegative(),
          }),
        )
        .max(500),
    })
    .nullable(),
  updates: z.object({
    manager: z.string().max(20).nullable(),
    pendingSecurity: z.number().int().nonnegative().nullable(),
    autoUpdates: z.boolean().nullable(),
  }),
  /** Backup Discovery (§5.3): tool names found in cron / systemd timers only. */
  backups: z
    .object({
      jobs: z.number().int().nonnegative(),
      tools: z.array(z.string().max(30)).max(30),
      codegateReporting: z.boolean(),
    })
    .nullable()
    .optional(),
});
export type AgentReport = z.infer<typeof agentReportSchema>;

// ─── BruteForce Shield (extension §4) ─────────────────────

const endpointPath = z
  .string()
  .min(1)
  .max(200)
  .regex(/^\/(?!\/)[^\s?#]*$/, "chemin absolu attendu, ex. /api/auth/login");

export const bruteForcePolicySchema = z.object({
  endpoint: endpointPath,
  maxAttempts: z.number().int().min(1).max(1000),
  windowSeconds: z.number().int().min(1).max(86_400),
  lockoutSeconds: z.number().int().min(0).max(86_400),
  strategy: z.enum(["fixed", "progressive"]).default("progressive"),
  applyTo: z.array(z.enum(["ip", "account", "device"])).min(1).default(["ip", "account"]),
  captchaAfter: z.number().int().min(1).max(1000).optional(),
  alertAfter: z.number().int().min(1).max(1000).optional(),
});
export type BruteForcePolicyInput = z.infer<typeof bruteForcePolicySchema>;

export const createBruteForceTargetSchema = z.object({
  name: z.string().min(1).max(100),
  /** Origin only (scheme + host [+ port]); HTTPS required. */
  origin: z
    .string()
    .url()
    .max(300)
    .refine((v) => v.startsWith("https://"), "HTTPS obligatoire"),
  environment: z.enum(["production", "staging", "development"]).default("staging"),
});
export type CreateBruteForceTargetInput = z.infer<typeof createBruteForceTargetSchema>;

export const BRUTEFORCE_TEST_TYPES = ["login_lockout", "account_enumeration"] as const;

export const runBruteForceTestSchema = z.object({
  targetId: z.string().uuid(),
  testType: z.enum(BRUTEFORCE_TEST_TYPES),
  endpoint: endpointPath,
  /** A dedicated test account — never a real user's (US03). */
  testAccount: z.string().min(1).max(320),
  emailField: z.string().min(1).max(50).default("email"),
  passwordField: z.string().min(1).max(50).default("password"),
  maxAttempts: z.number().int().min(1).max(20).default(12),
  /** Mandatory acknowledgement when the target is a production environment. */
  confirmProduction: z.boolean().default(false),
});
export type RunBruteForceTestInput = z.infer<typeof runBruteForceTestSchema>;

// ─── Backup Shield (extension §5) ─────────────────────────

export const BACKUP_TYPES = ["postgres", "mysql", "mongodb", "files", "other"] as const;
export const KEY_LOCATIONS = ["external_kms", "secret_manager", "offline", "same_server", "unknown"] as const;
export const STORAGE_LOCATIONS = ["offsite", "same_server", "local_disk", "unknown"] as const;

export const createBackupJobSchema = z.object({
  name: z.string().min(1).max(100),
  type: z.enum(BACKUP_TYPES),
  frequencyHours: z.number().int().min(1).max(24 * 31).default(24),
  serverId: z.string().uuid().optional(),
});
export type CreateBackupJobInput = z.infer<typeof createBackupJobSchema>;

/** One backup execution, as declared by `codegate-backup report`. */
export const backupRunReportSchema = z.object({
  finishedAt: z.string().datetime(),
  status: z.enum(["success", "failed"]),
  sizeBytes: z.number().nonnegative().nullable().default(null),
  durationSeconds: z.number().int().nonnegative().nullable().default(null),
  sha256: z.string().regex(/^[a-f0-9]{64}$/).nullable().default(null),
  encrypted: z.boolean(),
  encryptionAlgorithm: z.string().max(40).nullable().default(null),
  inTransit: z.enum(["tls1.3", "tls1.2", "ssh", "none", "unknown"]).default("unknown"),
  keyLocation: z.enum(KEY_LOCATIONS).default("unknown"),
  signed: z.boolean().default(false),
  storageProvider: z.string().max(60).nullable().default(null),
  storageLocation: z.enum(STORAGE_LOCATIONS).default("unknown"),
  immutable: z.boolean().nullable().default(null),
  versioning: z.boolean().nullable().default(null),
  separateAccount: z.boolean().nullable().default(null),
  retentionDays: z.number().int().min(0).max(36500).nullable().default(null),
});
export type BackupRunReport = z.infer<typeof backupRunReportSchema>;

/** Re-hash of a stored copy, compared to what was recorded at backup time. */
export const backupVerifyReportSchema = z.object({
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
});

export const restoreTestReportSchema = z.object({
  engine: z.enum(["postgres", "mysql", "mongodb", "files"]),
  startedAt: z.string().datetime(),
  completedAt: z.string().datetime(),
  durationSeconds: z.number().int().nonnegative(),
  result: z.enum(["success", "failed"]),
  restoredTables: z.number().int().nonnegative().nullable().default(null),
  restoredRecords: z.number().nonnegative().nullable().default(null),
  detail: z.string().max(500).nullable().default(null),
});
export type RestoreTestReport = z.infer<typeof restoreTestReportSchema>;

/** Pagination shared across list endpoints. */
export const paginationSchema = z.object({
  cursor: z.string().uuid().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});
export type PaginationInput = z.infer<typeof paginationSchema>;
