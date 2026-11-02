import type { DeployDecision, ProtectionLevel } from "@codegate/shared";

/**
 * Deploy Gate (cahier §5.5). Decides whether a deployment may proceed, based on
 * the security posture of what's being shipped and the repository's protection
 * level. Deterministic; separates the security verdict from enforcement, like
 * the PR policy engine.
 */

export interface DeployGateInput {
  openSecrets: number;
  criticalFindings: number;
  highFindings: number;
  criticalDependencies: number;
  /** Status of the most recent analyzed PR on the repo, if any. */
  latestPrBlocked: boolean;
}

export interface DeployGateResult {
  decision: DeployDecision;
  reason: string;
}

export function evaluateDeployGate(
  input: DeployGateInput,
  protectionLevel: ProtectionLevel,
): DeployGateResult {
  const hardRisk =
    input.openSecrets > 0 ||
    input.criticalFindings > 0 ||
    input.criticalDependencies > 0 ||
    input.latestPrBlocked;

  if (hardRisk) {
    const parts: string[] = [];
    if (input.openSecrets) parts.push(`${input.openSecrets} secret(s) exposé(s)`);
    if (input.criticalFindings) parts.push(`${input.criticalFindings} vulnérabilité(s) critique(s)`);
    if (input.criticalDependencies) parts.push(`${input.criticalDependencies} dépendance(s) critique(s)`);
    if (input.latestPrBlocked) parts.push("dernière PR bloquée");
    const detail = parts.join(", ");

    if (protectionLevel === "block") {
      return { decision: "blocked", reason: `Déploiement bloqué : ${detail}.` };
    }
    // observe/warn never hard-block.
    return { decision: "warning", reason: `Risque critique (non bloquant en mode ${protectionLevel}) : ${detail}.` };
  }

  if (input.highFindings > 0) {
    if (protectionLevel === "block") {
      return {
        decision: "requires_approval",
        reason: `${input.highFindings} problème(s) de sévérité élevée — approbation humaine requise.`,
      };
    }
    return { decision: "warning", reason: `${input.highFindings} problème(s) de sévérité élevée.` };
  }

  return { decision: "authorized", reason: "Aucun risque bloquant détecté." };
}
