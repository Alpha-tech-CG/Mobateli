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
  /** open | acknowledged | false_positive | accepted_risk | suppressed | resolved */
  status: string;
  fingerprint?: string | null;
  /** high | medium | low — how sure the match is, separate from severity. */
  confidence?: string | null;
  /** verified | likely | uncertain | information — how well it is proven. */
  assurance?: string | null;
  /** Evidence (masked), attack scenario, conditions, reproduction, CWE/OWASP. */
  details?: FindingDetails | null;
  /** When covered by an exception (status suppressed). */
  exceptionId?: string | null;
}

export interface FindingDetails {
  evidence?: string;
  scenario?: string;
  conditions?: string[];
  reproduction?: string;
  observationReason?: string;
  cwe?: string;
  owasp?: string;
}

/** Per-rule false-positive rate (pilot metric). */
export interface RuleQuality {
  ruleId: string;
  alerts: number;
  falsePositives: number;
  confirmed: number;
  falsePositiveRate: number | null;
}

export interface RuleQualityReport {
  days: number;
  alerts: number;
  reviewed: number;
  falsePositives: number;
  falsePositiveRate: number | null;
  rules: RuleQuality[];
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

export interface EngineReport {
  status: "ok" | "skipped" | "failed";
  detail?: string;
}

/** How the last analysis of a PR went (from its audit trail). */
export interface LastAnalysis {
  outcome: "analyzed" | "analysis_unavailable" | "analysis_failed";
  at: string;
  /** One entry per engine id (see ENGINE_IDS in @codegate/shared). */
  engines: Record<string, EngineReport>;
  reason?: string;
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
  | "tls"
  | "secrets"
  | "network"
  | "admin"
  | "http"
  | "daemon";

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
  evidence: string | null;
  verifyCommand: string | null;
  exploitScenario: string | null;
  exposure: "public" | "internal" | null;
  acceptance: ServerAcceptance | null;
}

export interface ServerAcceptance {
  checkId: string;
  kind: "accepted" | "mitigated";
  justification: string;
  expiresAt: string | null;
  createdAt: string;
}

export interface AttackChain {
  id: string;
  severity: Severity;
  title: string;
  steps: string[];
  checkIds: string[];
}

export interface ServerScanRow {
  id: string;
  score: number;
  critical: number;
  high: number;
  total: number;
  resolved: string[];
  introduced: string[];
  createdAt: string;
}

export interface ServerDetail extends Omit<ServerRow, "counts"> {
  agentVersion: string | null;
  lastReport: {
    listening: { proto: string; address: string; port: number; process: string | null }[];
  } | null;
  previousScore: number | null;
  rescanRequestedAt: string | null;
  analysis: {
    chains: AttackChain[];
    mitigations: string[];
    acceptedCount: number;
    resolved: string[];
    introduced: string[];
  } | null;
  findings: ServerFinding[];
  scans: ServerScanRow[];
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
  fragility?: { score: number; grade: FragilityGrade } | null;
}

// ─── Architecture (graph, fragility, blast radius) ─────────────────────────

export type ArchRole = "entry" | "ui" | "service" | "data" | "auth" | "config";
export type FragilityGrade = "solide" | "correcte" | "fragile" | "très fragile";
export type SensitiveKind = "data" | "auth" | "config";

export interface ArchModule {
  id: string;
  label: string;
  role: ArchRole;
  files: number;
  loc: number;
  fanIn: number;
  fanOut: number;
  instability: number;
  inCycle: boolean;
  sensitive: SensitiveKind[];
  issues: { critical: number; high: number; medium: number; low: number };
}

export interface ArchEdge {
  from: string;
  to: string;
  weight: number;
  cycle: boolean;
  mutual: boolean;
  violation: boolean;
}

export interface BlastRadius {
  key: string;
  kind: "finding" | "secret";
  title: string;
  severity: Severity;
  location: string;
  module: string | null;
  impactScore: number;
  level: "critique" | "élevé" | "modéré" | "limité";
  dependents: number;
  reachPercent: number;
  entryPoints: string[];
  assets: { file: string; kind: SensitiveKind }[];
  impactedModules: string[];
  exposedModules: string[];
  assetModules: string[];
  narrative: string;
}

export interface ArchitectureReport {
  version: 1;
  stats: {
    sourceFiles: number;
    imports: number;
    externalPackages: number;
    entryPoints: number;
    filesInCycles: number;
    cycles: number;
    layerViolations: number;
    orphanFiles: number;
    languages: string[];
  };
  fragility: {
    score: number;
    grade: FragilityGrade;
    factors: { id: string; label: string; points: number; max: number; detail: string }[];
    summary: string;
    projectedScore: number;
  };
  modules: ArchModule[];
  edges: ArchEdge[];
  blast: BlastRadius[];
  proposals: {
    id: string;
    priority: 1 | 2 | 3;
    title: string;
    problem: string;
    actions: string[];
    advantage: string;
    effort: "faible" | "moyen" | "élevé";
    gain: number;
    targets: string[];
  }[];
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
    dependencies: {
      ecosystem: string;
      name: string;
      version: string;
      /** Installed version from a lockfile; `version` is the declared range. */
      resolvedVersion?: string;
      trustScore: number;
      riskLevel: string;
      reason?: string;
    }[];
    suppressed: number;
    /** Absent on scans made before the architecture analysis existed. */
    architecture?: ArchitectureReport | null;
  } | null;
}
