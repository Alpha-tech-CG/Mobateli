import { z } from "zod";
import {
  ROLES,
  SEVERITIES,
  AGENT_PERMISSIONS,
  AGENT_DECISIONS,
  FINDING_STATUSES,
} from "./enums.js";

/**
 * Zod schemas for API input validation. These are the single source of truth
 * for request shapes — the API validates every input against them (cahier §13.4).
 */

// Normalized: "Zlat@CodeGate.dev " and "zlat@codegate.dev" are one account —
// otherwise a capital letter at login reads as "no such user".
export const emailSchema = z.string().trim().toLowerCase().email().max(320);

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

/** One-time token from an email link (base64url, 256 bits). */
const emailTokenSchema = z.string().regex(/^[A-Za-z0-9_-]{20,100}$/, "Lien invalide");

export const forgotPasswordSchema = z.object({ email: emailSchema });
export const resetPasswordSchema = z.object({ token: emailTokenSchema, password: passwordSchema });
export const verifyEmailSchema = z.object({ token: emailTokenSchema });
export const acceptInviteSchema = z.object({
  token: emailTokenSchema,
  password: passwordSchema,
  name: z.string().trim().min(1).max(120).optional(),
});

export const inviteMemberSchema = z.object({
  email: emailSchema,
  role: z.enum(ROLES),
});
export type InviteMemberInput = z.infer<typeof inviteMemberSchema>;

export const updateMemberSchema = z
  .object({ role: z.enum(ROLES).optional(), active: z.boolean().optional() })
  .refine((v) => v.role !== undefined || v.active !== undefined, "role ou active requis");
export type UpdateMemberInput = z.infer<typeof updateMemberSchema>;

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

export const connectGitlabApiSchema = z.object({
  baseUrl: z
    .string()
    .url()
    .max(300)
    .refine((v) => v.startsWith("https://"), "HTTPS obligatoire")
    .default("https://gitlab.com"),
  /** Project/group access token with `api` scope (encrypted at rest). */
  accessToken: z.string().min(10).max(500),
});

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

export const findingsQuerySchema = z.object({
  repositoryId: z.string().uuid().optional(),
  status: z.enum(FINDING_STATUSES).optional(),
  severity: z.enum(SEVERITIES).optional(),
  limit: z.coerce.number().int().min(1).max(500).default(200),
});

export const updateFindingSchema = z.object({
  status: z.enum(FINDING_STATUSES),
  /** Why it is a false positive / accepted — kept in the audit trail. */
  reason: z.string().max(500).optional(),
});
export type UpdateFindingInput = z.infer<typeof updateFindingSchema>;

export const approvalsQuerySchema = z.object({
  status: z.enum(["pending", "approved", "denied", "expired"]).optional(),
});

export const approvalDecisionSchema = z.object({
  decision: z.enum(["approve", "deny"]),
  reason: z.string().max(500).optional(),
});

export const updateRepositorySchema = z.object({
  autoScan: z.boolean(),
});

export const deleteOrganizationSchema = z.object({
  /** The exact organization name, typed by the owner to confirm. */
  confirmName: z.string().min(1).max(200),
});

export const githubManifestStartSchema = z.object({
  /** Public App name on GitHub (globally unique there). */
  name: z.string().min(3).max(34),
  /** Create the App under this GitHub organization instead of the user account. */
  githubOrganization: z.string().regex(/^[A-Za-z0-9-]{1,39}$/).optional(),
});

export const githubManifestCompleteSchema = z.object({
  code: z.string().min(10).max(200),
  state: z.string().min(20).max(2000),
});

export const linkGithubSchema = z.object({
  installationId: z.coerce.number().int().positive(),
  state: z.string().min(20).max(2000),
  /**
   * One-time OAuth code GitHub adds when the App requests user authorization
   * during installation: proves the user can access the installation.
   */
  code: z.string().min(1).max(200).optional(),
});

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
    /** Ports UFW allows from anywhere, e.g. [22, 80, 443] (agent ≥ 2.0). */
    ufwAllowed: z.array(z.number().int()).max(500).nullable().optional(),
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
            // Agent ≥ 2.0 — all optional so older agents keep reporting.
            /** Host paths mounted in the container (paths only, never contents). */
            mounts: z
              .array(z.object({ source: z.string().max(500), destination: z.string().max(500), rw: z.boolean() }))
              .max(200)
              .optional(),
            /** UID of the container's main process as seen by the host kernel. */
            effectiveUid: z.number().int().nullable().optional(),
            networkMode: z.string().max(100).optional(),
            networks: z.array(z.string().max(100)).max(50).optional(),
            noNewPrivileges: z.boolean().optional(),
            capDrop: z.array(z.string().max(60)).max(60).optional(),
            /** Hostnames routed to this container (Traefik Host() rules). */
            routedHosts: z.array(z.string().max(255)).max(50).optional(),
            /** Auth middleware on its routes: none, ok, or broken (users file missing). */
            routeAuth: z.enum(["none", "ok", "broken"]).optional(),
            /** Names (never values) of environment variables holding a literal secret. */
            secretEnvNames: z.array(z.string().max(100)).max(100).optional(),
            /** For socket proxies: is the write API (POST) enabled? */
            socketProxyPost: z.boolean().nullable().optional(),
          }),
        )
        .max(500),
      /** /etc/docker/daemon.json hardening flags (null when unreadable). */
      daemon: z
        .object({
          usernsRemap: z.boolean(),
          liveRestore: z.boolean(),
          noNewPrivileges: z.boolean(),
          logMaxSize: z.boolean(),
        })
        .nullable()
        .optional(),
      /** .env files of compose projects: path and permission bits only. */
      envFiles: z
        .array(z.object({ path: z.string().max(500), mode: z.string().max(6), worldReadable: z.boolean() }))
        .max(100)
        .optional(),
    })
    .nullable(),
  updates: z.object({
    manager: z.string().max(20).nullable(),
    pendingSecurity: z.number().int().nonnegative().nullable(),
    autoUpdates: z.boolean().nullable(),
    /** Days since unattended-upgrades last ran (agent ≥ 2.0). */
    autoUpdatesLastRunDays: z.number().int().nullable().optional(),
  }),
  /** Host accounts (agent ≥ 2.0): names only. */
  host: z
    .object({
      uid0Accounts: z.array(z.string().max(64)).max(50),
      /** Principals allowed "NOPASSWD: ALL" in sudoers; null when unreadable. */
      passwordlessSudo: z.array(z.string().max(64)).max(50).nullable(),
    })
    .optional(),
  /** TLS Audit (§3.2): local HTTPS listeners, probed on 127.0.0.1. */
  tls: z
    .array(
      z.object({
        port: z.number().int(),
        protocol: z.string().max(20).nullable(),
        legacyAccepted: z.boolean().nullable(),
        certExpiresInDays: z.number().int().nullable(),
        selfSigned: z.boolean().nullable(),
        /** Hostname sent as SNI (agent ≥ 2.0); absent = default certificate. */
        sni: z.string().max(255).nullable().optional(),
        /** Chain and hostname validated against the system trust store. */
        trusted: z.boolean().nullable().optional(),
        issuer: z.string().max(200).nullable().optional(),
        /** Security headers returned on GET / for this hostname. */
        headers: z
          .object({
            hsts: z.boolean(),
            csp: z.boolean(),
            frameOptions: z.boolean(),
            contentTypeOptions: z.boolean(),
          })
          .nullable()
          .optional(),
      }),
    )
    .max(100)
    .optional(),
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

/** Accept a server finding as a known risk, or record the control mitigating it (P1-9). */
export const serverRiskAcceptanceSchema = z.object({
  kind: z.enum(["accepted", "mitigated"]),
  justification: z.string().trim().min(10).max(1000),
  /** Optional review date; the finding counts again after it. */
  expiresAt: z.string().datetime().optional(),
});
export type ServerRiskAcceptanceInput = z.infer<typeof serverRiskAcceptanceSchema>;

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
