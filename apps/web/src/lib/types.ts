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
