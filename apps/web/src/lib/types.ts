export type Severity = "info" | "low" | "medium" | "high" | "critical";
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
  counts: { findings: number; secrets: number; dependencies: number };
  createdAt: string;
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
