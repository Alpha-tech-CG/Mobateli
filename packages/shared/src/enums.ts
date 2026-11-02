/**
 * Domain enums shared across the API, workers and data layer.
 * Kept as string unions + const arrays so they're usable both as TS types
 * and as runtime values (Zod, Prisma seed, validation).
 */

export const ROLES = [
  "owner",
  "admin",
  "security_manager",
  "developer",
  "auditor",
  "viewer",
] as const;
export type Role = (typeof ROLES)[number];

export const SCM_PROVIDERS = ["github", "gitlab"] as const;
export type ScmProvider = (typeof SCM_PROVIDERS)[number];

/** Repository protection level — cf. cahier §6.1 */
export const PROTECTION_LEVELS = ["observe", "warn", "block"] as const;
export type ProtectionLevel = (typeof PROTECTION_LEVELS)[number];

export const PR_STATUSES = [
  "pending",
  "analyzing",
  "passed",
  "warning",
  "blocked",
  "escalated",
] as const;
export type PullRequestStatus = (typeof PR_STATUSES)[number];

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const FINDING_TYPES = [
  "secret",
  "dependency",
  "sast",
  "config",
  "auth",
  "prompt_injection",
] as const;
export type FindingType = (typeof FINDING_TYPES)[number];

export const FINDING_STATUSES = [
  "open",
  "acknowledged",
  "resolved",
  "false_positive",
] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const DEPENDENCY_RISK = ["low", "medium", "high", "critical"] as const;
export type DependencyRisk = (typeof DEPENDENCY_RISK)[number];

/** Decision produced by the Risk Decision Engine — cf. cahier §1 */
export const DECISIONS = ["allow", "fix", "block", "escalate"] as const;
export type Decision = (typeof DECISIONS)[number];

/** Policy action when a threshold is crossed */
export const POLICY_ACTIONS = ["allow", "warn", "block", "require_approval"] as const;
export type PolicyAction = (typeof POLICY_ACTIONS)[number];

export const ACTOR_TYPES = ["user", "ai_agent", "system"] as const;
export type ActorType = (typeof ACTOR_TYPES)[number];

/** Actions an AI agent may attempt — cf. cahier §5.4 */
export const AGENT_PERMISSIONS = [
  "read_repo",
  "modify_file",
  "install_dependency",
  "run_shell",
  "network_access",
  "modify_secrets",
  "deploy_production",
  "delete_files",
] as const;
export type AgentPermission = (typeof AGENT_PERMISSIONS)[number];

export const AGENT_DECISIONS = ["allow", "deny", "require_approval"] as const;
export type AgentDecision = (typeof AGENT_DECISIONS)[number];

/** Outcome of the Vercel Deploy Gate — cf. cahier §5.5 */
export const DEPLOY_DECISIONS = [
  "authorized",
  "warning",
  "blocked",
  "requires_approval",
] as const;
export type DeployDecision = (typeof DEPLOY_DECISIONS)[number];
