export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Role = "owner" | "admin" | "security_manager" | "developer" | "auditor" | "viewer";
export type PullRequestStatus =
  | "pending"
  | "analyzing"
  | "passed"
  | "warning"
  | "blocked"
  | "escalated";

export interface Organization {
  id: string;
  name: string;
  plan: string;
  region: string;
  createdAt: string;
}

export interface Member {
  id: string;
  email: string;
  name: string;
  role: string;
  mfaEnabled: boolean;
  createdAt: string;
}

export interface Policy {
  id: string;
  repositoryId: string | null;
  rule: string;
  action: "allow" | "warn" | "block" | "require_approval";
  severityThreshold: Severity;
  createdAt: string;
}

export type DeployDecision = "authorized" | "warning" | "blocked" | "requires_approval";

export interface DeployCheckRow {
  id: string;
  repository: string;
  provider: string;
  target: string | null;
  commitSha: string | null;
  decision: DeployDecision;
  reason: string;
  createdAt: string;
}

export interface Repository {
  id: string;
  name: string;
  provider: string;
  defaultBranch: string;
  protectionLevel: string;
}

export type AgentPermission =
  | "read_repo"
  | "modify_file"
  | "install_dependency"
  | "run_shell"
  | "network_access"
  | "modify_secrets"
  | "deploy_production"
  | "delete_files";

export type AgentDecision = "allow" | "deny" | "require_approval";

export interface AgentPolicyRow {
  permission: AgentPermission;
  decision: AgentDecision;
  allowlist: string[];
  source: "default" | "organization" | "repository";
}

export interface AuditEvent {
  id: string;
  createdAt: string;
  actorType: string;
  actorId: string | null;
  action: string;
  resourceType: string;
  resourceId: string | null;
  metadata: unknown;
}

export interface PullRequestListItem {
  id: string;
  number: number;
  title: string;
  author: string;
  aiGenerated: boolean;
  riskScore: number | null;
  status: PullRequestStatus;
  repository: string;
  repositoryId: string;
  provider: "github" | "gitlab";
  /** Problems only; `dependenciesAnalyzed` is every dependency the PR adds. */
  counts: { findings: number; secrets: number; dependencies: number; dependenciesAnalyzed: number };
  createdAt: string;
}

export interface OpenPullRequest {
  number: number;
  title: string;
  author: string;
  url: string;
  updatedAt: string;
  analysis: { id: string; riskScore: number | null; status: PullRequestStatus; upToDate: boolean } | null;
}

export interface Finding {
  id: string;
  type: string;
  severity: Severity;
  title: string;
  description: string;
  filePath: string | null;
  line: number | null;
  ruleId: string | null;
  remediation: string | null;
  status: string;
}

export interface SecretFinding {
  id: string;
  secretType: string;
  location: string;
  maskedPreview: string;
  status: string;
  revokedAt?: string | null;
}

export interface Dependency {
  id: string;
  ecosystem: string;
  name: string;
  version: string;
  trustScore: number | null;
  riskLevel: "low" | "medium" | "high" | "critical";
  reason: string | null;
}

export interface PullRequestDetail {
  id: string;
  number: number;
  title: string;
  author: string;
  aiGenerated: boolean;
  riskScore: number | null;
  status: PullRequestStatus;
  headSha: string | null;
  repository: { name: string; protectionLevel: string };
  findings: Finding[];
  dependencies: Dependency[];
  secretFindings: SecretFinding[];
}

// ─── Infra Shield ───────────────────────────────────────

export type InfraCategory =
  | "ports"
  | "ssh"
  | "firewall"
  | "bruteforce"
  | "docker"
  | "updates"
  | "backups"
  | "tls";

export interface ServerRow {
  id: string;
  name: string;
  provider: string | null;
  environment: string;
  hostname: string | null;
  os: string | null;
  securityScore: number | null;
  lastReportAt: string | null;
  createdAt: string;
  counts: { critical: number; high: number; total: number };
}

export interface ServerFinding {
  id: string;
  category: InfraCategory;
  checkId: string;
  severity: Severity;
  title: string;
  detail: string;
  recommendation: string;
}

export interface ServerDetail extends Omit<ServerRow, "counts"> {
  agentVersion: string | null;
  lastReport: {
    listening: { proto: string; address: string; port: number; process: string | null }[];
  } | null;
  findings: ServerFinding[];
}

// ─── BruteForce Shield ──────────────────────────────────

export interface BruteForcePolicy {
  id: string;
  endpoint: string;
  maxAttempts: number;
  windowSeconds: number;
  lockoutSeconds: number;
  strategy: "fixed" | "progressive";
  applyTo: string[];
  captchaAfter: number | null;
  alertAfter: number | null;
}

export interface BruteForceTarget {
  id: string;
  name: string;
  origin: string;
  environment: string;
  verificationToken: string;
  verifiedAt: string | null;
}

export type BruteForceResult = "pass" | "warn" | "fail";

export interface BruteForceTestRow {
  id: string;
  testType: "login_lockout" | "account_enumeration";
  endpoint: string;
  attempts: number;
  blockedAfter: number | null;
  scope: "account" | "ip" | null;
  result: BruteForceResult;
  summary: string;
  evidence: {
    observations?: { attempt: number; status: number; ms: number; blocked: boolean }[];
    existing?: { attempt: number; status: number; ms: number }[];
    missing?: { attempt: number; status: number; ms: number }[];
    testAccount?: string;
  };
  createdAt: string;
  target: { name: string; origin: string; environment: string };
}

// ─── Backup Shield ──────────────────────────────────────

export type BackupStatus = "healthy" | "attention" | "critical";

export interface BackupRow {
  id: string;
  name: string;
  type: string;
  frequencyHours: number;
  server: string | null;
  lastRunAt: string | null;
  lastRestoreAt: string | null;
  score: number;
  status: BackupStatus;
  ransomwareReady: boolean;
  failedChecks: number;
}

export interface BackupCheck {
  id: string;
  label: string;
  ok: boolean;
  severity: Severity;
  detail: string;
  recommendation: string | null;
}

export interface BackupRunRow {
  id: string;
  finishedAt: string;
  status: string;
  sizeBytes: number | null;
  durationSeconds: number | null;
  sha256: string | null;
  encrypted: boolean;
  encryptionAlgorithm: string | null;
  storageProvider: string | null;
  storageLocation: string;
  integrityOk: boolean | null;
}

export interface RestoreTestRow {
  id: string;
  engine: string;
  completedAt: string;
  durationSeconds: number;
  result: string;
  restoredTables: number | null;
  restoredRecords: number | null;
  detail: string | null;
}

export interface BackupDetail {
  id: string;
  name: string;
  type: string;
  frequencyHours: number;
  server: { id: string; name: string } | null;
  runs: BackupRunRow[];
  restoreTests: RestoreTestRow[];
}

export interface BackupEvaluation {
  score: number;
  status: BackupStatus;
  ransomwareReady: boolean;
  checks: BackupCheck[];
}

// ─── Approbations & membres ─────────────────────────────

export interface ApprovalRow {
  id: string;
  kind: "agent_action" | "deployment";
  title: string;
  detail: { reason?: string; permission?: string; target?: string | null; agentId?: string | null };
  status: "pending" | "approved" | "denied" | "expired";
  reason: string | null;
  expiresAt: string;
  decidedAt: string | null;
  createdAt: string;
}

export interface MemberRow {
  id: string;
  email: string;
  name: string;
  role: Role;
  mfaEnabled: boolean;
  active: boolean;
  createdAt: string;
}

export interface RevocationGuide {
  provider: string;
  url: string | null;
  steps: string[];
}

// ─── Analyses de dépôts ─────────────────────────────────

export type ScanStatus = "queued" | "running" | "done" | "failed";
export type ScanPhase = "download" | "extract" | "analysis" | "dependencies" | "done";

export interface RepositoryRow {
  id: string;
  name: string;
  provider: "github" | "gitlab";
  defaultBranch: string;
  autoScan: boolean;
  scannable: boolean;
  lastScan: { id: string; status: ScanStatus; riskScore: number | null; finishedAt: string | null; createdAt: string } | null;
}

export interface ScanSummary {
  files: number;
  skippedFiles: number;
  truncated: boolean;
  secrets: number;
  findings: number;
  informational: number;
  riskyDependencies: number;
  bySeverity: Record<string, number>;
  engine: string;
}

export interface ScanRow {
  id: string;
  trigger: "manual" | "auto" | "connect";
  status: ScanStatus;
  phase: ScanPhase | null;
  ref: string | null;
  commitSha: string | null;
  filesScanned: number;
  riskScore: number | null;
  decision: string | null;
  summary: ScanSummary | null;
  error: string | null;
  createdAt: string;
  finishedAt: string | null;
  repository: { id: string; name: string; provider: string };
}

export interface ScanDetail extends ScanRow {
  result: {
    secrets: { secretType: string; location: string; maskedPreview: string; severity: Severity }[];
    findings: { type: string; severity: Severity; title: string; description: string; filePath?: string; line?: number; remediation?: string }[];
    dependencies: { ecosystem: string; name: string; version: string; trustScore: number; riskLevel: string; reason?: string }[];
    suppressed: number;
  } | null;
}
