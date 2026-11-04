"use client";

import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { api } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";
import type {
  AgentDecision,
  AgentPermission,
  AgentPolicyRow,
  Repository,
} from "@/lib/types";

const DECISIONS: AgentDecision[] = ["allow", "deny", "require_approval"];
const DECISION_STYLE: Record<AgentDecision, string> = {
  allow: "text-success",
  deny: "text-destructive",
  require_approval: "text-warning",
};

export default function AgentGuardPage() {
  return (
    <Shell>
      <AgentGuard />
    </Shell>
  );
}

function AgentGuard() {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [repoId, setRepoId] = useState<string>("");
  const [policies, setPolicies] = useState<AgentPolicyRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<{ repositories: Repository[] }>("/api/v1/repositories")
      .then((r) => {
        setRepos(r.repositories);
        if (r.repositories[0]) setRepoId(r.repositories[0].id);
      })
      .catch(() => setError("Impossible de charger les dépôts."));
  }, []);

  useEffect(() => {
    if (!repoId) return;
    api<{ policies: AgentPolicyRow[] }>(`/api/v1/repositories/${repoId}/agent-policies`)
      .then((r) => setPolicies(r.policies))
      .catch(() => setError("Impossible de charger les politiques d'agent."));
  }, [repoId]);

  async function save(permission: AgentPermission, decision: AgentDecision, allowlist: string[]) {
    await api(`/api/v1/repositories/${repoId}/agent-policies`, {
      method: "PUT",
      body: JSON.stringify({ permission, decision, allowlist }),
    });
    const r = await api<{ policies: AgentPolicyRow[] }>(
      `/api/v1/repositories/${repoId}/agent-policies`,
    );
    setPolicies(r.policies);
  }

  return (
    <div>
      <header className="mb-6 flex items-center gap-3">
        <ShieldAlert className="size-6 text-primary" aria-hidden />
        <div>
          <h1 className="text-xl font-semibold">Agent Guard</h1>
          <p className="text-sm text-muted-foreground">
            Ce qu&apos;un agent IA peut faire sur ce dépôt — secrets jamais modifiables.
          </p>
        </div>
      </header>

      {error ? <Card className="mb-4 p-4 text-sm text-destructive">{error}</Card> : null}

      <div className="mb-4">
        <label className="text-xs font-medium text-muted-foreground">Dépôt</label>
        <select
          value={repoId}
          onChange={(e) => setRepoId(e.target.value)}
          className="ml-2 cursor-pointer rounded-md border border-border bg-background px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-ring"
        >
          {repos.map((r) => (
            <option key={r.id} value={r.id}>
              {r.name}
            </option>
          ))}
        </select>
      </div>

      <Card className="mb-8">
        <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-muted-foreground">
              <th className="px-4 py-2 font-medium">Permission</th>
              <th className="px-4 py-2 font-medium">Décision</th>
              <th className="px-4 py-2 font-medium">Liste blanche</th>
              <th className="px-4 py-2 font-medium">Source</th>
            </tr>
          </thead>
          <tbody>
            {policies.map((p) => (
              <PolicyRow key={p.permission} row={p} onSave={save} />
            ))}
          </tbody>
        </table>
        </div>
      </Card>

      {repoId ? <Simulator repoId={repoId} /> : null}
    </div>
  );
}

function PolicyRow({
  row,
  onSave,
}: {
  row: AgentPolicyRow;
  onSave: (p: AgentPermission, d: AgentDecision, a: string[]) => Promise<void>;
}) {
  const locked = row.permission === "modify_secrets";
  const [decision, setDecision] = useState<AgentDecision>(row.decision);
  const [allow, setAllow] = useState(row.allowlist.join(", "));
  const [busy, setBusy] = useState(false);
  const dirty = decision !== row.decision || allow !== row.allowlist.join(", ");

  async function save() {
    setBusy(true);
    try {
      await onSave(
        row.permission,
        decision,
        allow.split(",").map((s) => s.trim()).filter(Boolean),
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <tr className="border-b border-border last:border-0 hover:bg-muted/50">
      <td className="px-4 py-2 font-mono text-xs">{row.permission}</td>
      <td className="px-4 py-2">
        <select
          value={decision}
          disabled={locked}
          onChange={(e) => setDecision(e.target.value as AgentDecision)}
          className={`cursor-pointer rounded-md border border-border bg-background px-2 py-1 text-xs outline-none focus:ring-2 focus:ring-ring disabled:opacity-60 ${DECISION_STYLE[decision]}`}
        >
          {DECISIONS.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
      </td>
      <td className="px-4 py-2">
        <input
          value={allow}
          disabled={locked}
          onChange={(e) => setAllow(e.target.value)}
          placeholder="ex: zod, api.github.com"
          className="w-56 rounded-md border border-border bg-background px-2 py-1 font-mono text-xs outline-none focus:ring-2 focus:ring-ring disabled:opacity-60"
        />
      </td>
      <td className="px-4 py-2 text-xs text-muted-foreground">
        {locked ? (
          <span className="text-destructive">verrouillé</span>
        ) : dirty ? (
          <button
            onClick={save}
            disabled={busy}
            className="cursor-pointer rounded-md bg-primary px-2 py-1 text-xs font-medium text-on-primary hover:opacity-90 disabled:opacity-50"
          >
            {busy ? "…" : "Enregistrer"}
          </button>
        ) : (
          row.source
        )}
      </td>
    </tr>
  );
}

function Simulator({ repoId }: { repoId: string }) {
  const [permission, setPermission] = useState<AgentPermission>("run_shell");
  const [target, setTarget] = useState("rm -rf /");
  const [result, setResult] = useState<{ decision: AgentDecision; reason: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const perms: AgentPermission[] = [
    "read_repo",
    "modify_file",
    "install_dependency",
    "run_shell",
    "network_access",
    "modify_secrets",
    "deploy_production",
    "delete_files",
  ];

  async function run() {
    setBusy(true);
    try {
      const r = await api<{ decision: AgentDecision; reason: string }>("/api/v1/agent/guard", {
        method: "POST",
        body: JSON.stringify({ repositoryId: repoId, permission, target, agentId: "simulateur" }),
      });
      setResult(r);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
        Simulateur d&apos;action
      </h2>
      <Card className="p-4">
        <div className="flex flex-wrap items-end gap-3">
          <label>
            <span className="mb-1 block text-xs font-medium text-muted-foreground">Permission</span>
            <select
              value={permission}
              onChange={(e) => setPermission(e.target.value as AgentPermission)}
              className="cursor-pointer rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
            >
              {perms.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </label>
          <label className="flex-1 min-w-48">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">
              Cible (paquet / domaine / commande)
            </span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
            />
          </label>
          <button
            onClick={run}
            disabled={busy}
            className="cursor-pointer rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary hover:opacity-90 disabled:opacity-50"
          >
            {busy ? "…" : "Tester"}
          </button>
        </div>
        {result ? (
          <div className="mt-4 rounded-md border border-border p-3 text-sm">
            <span className={`font-semibold ${DECISION_STYLE[result.decision]}`}>
              {result.decision}
            </span>{" "}
            — {result.reason}
          </div>
        ) : null}
      </Card>
    </div>
  );
}
