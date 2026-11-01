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
