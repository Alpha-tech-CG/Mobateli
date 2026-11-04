import type { AgentDecision, AgentPermission } from "@codegate/shared";

/**
 * Agent Guard (cahier §5.4). Decides whether an AI agent action is allowed,
 * denied, or needs human approval. Deterministic, with secure built-in
 * defaults and one non-negotiable invariant: secrets are never writable.
 */

export interface AgentRule {
  decision: AgentDecision;
  allowlist: string[];
}

export interface GuardResult {
  decision: AgentDecision;
  reason: string;
}

/** Secure defaults — the baseline from the cahier §5.4 table. */
export const AGENT_DEFAULTS: Record<AgentPermission, AgentRule> = {
  read_repo: { decision: "allow", allowlist: [] },
  modify_file: { decision: "allow", allowlist: [] },
  install_dependency: { decision: "require_approval", allowlist: [] },
  run_shell: { decision: "require_approval", allowlist: [] },
  network_access: { decision: "deny", allowlist: [] },
  modify_secrets: { decision: "deny", allowlist: [] },
  deploy_production: { decision: "require_approval", allowlist: [] },
  delete_files: { decision: "require_approval", allowlist: [] },
};

/**
 * Resolve the effective rule for one permission: repo rule wins over org rule,
 * which wins over the built-in default.
 */
export function resolveRule(
  permission: AgentPermission,
  orgRule: AgentRule | undefined,
  repoRule: AgentRule | undefined,
): AgentRule {
  return repoRule ?? orgRule ?? AGENT_DEFAULTS[permission];
}

/** Shell operators that chain, pipe, redirect or substitute commands. */
const SHELL_META = /[;&|`$<>\n\r(){}]/;

/** Hostname of a URL or `host[:port]`, lowercased; null when unparseable. */
function toHostname(target: string): string | null {
  const raw = target.trim();
  try {
    const host = new URL(raw.includes("://") ? raw : `http://${raw}`).hostname;
    return host ? host.toLowerCase().replace(/\.$/, "") : null;
  } catch {
    return null;
  }
}

/** Does `target` match an allowlist entry, per permission semantics? */
function matchesAllowlist(
  permission: AgentPermission,
  target: string | undefined,
  allowlist: string[],
): boolean {
  if (!target || allowlist.length === 0) return false;
  if (permission === "network_access") {
    // Exact host or subdomain of an allowed domain. The target is reduced to
    // a bare hostname first, so "https://evil.com/x.allowed.com" or
    // "evil.com#.allowed.com" can't pass a suffix check.
    const host = toHostname(target);
    if (!host) return false;
    return allowlist.some((entry) => {
      const d = entry.toLowerCase().replace(/\.$/, "");
      return host === d || host.endsWith(`.${d}`);
    });
  }
  if (permission === "run_shell") {
    // Command must start with an allowed command/prefix, and must not chain or
    // substitute another command ("npm test && curl … | sh").
    if (SHELL_META.test(target)) return false;
    return allowlist.some((c) => target === c || target.startsWith(`${c} `));
  }
  // Packages, paths: exact match.
  return allowlist.includes(target);
}

export function evaluateAgentAction(params: {
  permission: AgentPermission;
  rule: AgentRule;
  target?: string;
}): GuardResult {
  const { permission, rule, target } = params;

  // Invariant: an agent may NEVER write secrets, whatever a policy says.
  if (permission === "modify_secrets") {
    return { decision: "deny", reason: "Modification des secrets interdite par principe (non dérogeable)." };
  }

  const onAllowlist = matchesAllowlist(permission, target, rule.allowlist);

  if (rule.decision === "allow") {
    return { decision: "allow", reason: "Autorisé par la politique." };
  }

  if (onAllowlist) {
    return {
      decision: "allow",
      reason: `« ${target} » figure sur la liste blanche de ${permission}.`,
    };
  }

  if (rule.decision === "deny") {
    return {
      decision: "deny",
      reason: target
        ? `« ${target} » n'est pas sur la liste blanche de ${permission} — bloqué.`
        : `${permission} est interdit par la politique.`,
    };
  }

  return {
    decision: "require_approval",
    reason: `${permission} nécessite une approbation humaine.`,
  };
}
