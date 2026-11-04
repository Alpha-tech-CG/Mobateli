"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card, KpiCard } from "@/components/ui";
import type { Member, Organization, Policy } from "@/lib/types";

export default function OverviewPage() {
  return (
    <Shell>
      <Overview />
    </Shell>
  );
}

function Overview() {
  const [org, setOrg] = useState<Organization | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [reset, setReset] = useState<{ email: string; tempPassword?: string; error?: string } | null>(
    null,
  );

  async function resetPassword(m: Member) {
    if (!window.confirm(`Réinitialiser le mot de passe de ${m.email} ?`)) return;
    try {
      const r = await api<{ tempPassword: string }>(
        `/api/v1/organization/members/${m.id}/reset-password`,
        { method: "POST" },
      );
      setReset({ email: m.email, tempPassword: r.tempPassword });
    } catch {
      setReset({ email: m.email, error: "Réinitialisation refusée (droits insuffisants ?)." });
    }
  }

  useEffect(() => {
    Promise.all([
      api<Organization>("/api/v1/organization"),
      api<{ members: Member[] }>("/api/v1/organization/members"),
      api<{ policies: Policy[] }>("/api/v1/policies"),
    ])
      .then(([o, m, p]) => {
        setOrg(o);
        setMembers(m.members);
        setPolicies(p.policies);
      })
      .catch(() => setError("Impossible de charger les données. L'API est-elle démarrée ?"));
  }, []);

  return (
    <div>
      <header className="mb-6">
        <h1 className="text-xl font-semibold">Vue d'ensemble</h1>
        <p className="text-sm text-muted-foreground">
          {org ? org.name : "Chargement…"} · hébergement {org?.region.toUpperCase() ?? "—"}
        </p>
      </header>

      {error ? (
        <Card className="p-4 text-sm text-destructive">{error}</Card>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <KpiCard label="Plan" value={org?.plan ?? "—"} />
            <KpiCard label="Membres" value={members.length} />
            <KpiCard label="Politiques" value={policies.length} hint="règles de sécurité actives" />
            <KpiCard label="Région" value={org?.region?.toUpperCase() ?? "—"} hint="RGPD / UE" />
          </div>

          <h2 className="mt-8 mb-3 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            Membres
          </h2>
          {reset ? (
            <Card className="mb-3 p-4 text-sm">
              {reset.tempPassword ? (
                <>
                  <p>
                    Mot de passe temporaire de <span className="font-mono">{reset.email}</span> —
                    transmettez-le par un canal sûr, il ne sera plus affiché :
                  </p>
                  <code className="mt-2 block break-all rounded bg-muted px-2 py-1 font-mono">
                    {reset.tempPassword}
                  </code>
                </>
              ) : (
                <p className="text-destructive">{reset.error}</p>
              )}
            </Card>
          ) : null}
          <Card>
            <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="px-4 py-2 font-medium">Email</th>
                  <th className="px-4 py-2 font-medium">Rôle</th>
                  <th className="px-4 py-2 font-medium">MFA</th>
                  <th className="px-4 py-2 font-medium">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {members.map((m) => (
                  <tr key={m.id} className="border-b border-border last:border-0 hover:bg-muted/50">
                    <td className="px-4 py-2 font-mono text-xs">{m.email}</td>
                    <td className="px-4 py-2">{m.role}</td>
                    <td className="px-4 py-2">{m.mfaEnabled ? "activé" : "—"}</td>
                    <td className="px-4 py-2 text-right">
                      <button
                        onClick={() => resetPassword(m)}
                        className="cursor-pointer whitespace-nowrap text-xs text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
                      >
                        Réinitialiser le mot de passe
                      </button>
                    </td>
                  </tr>
                ))}
                {!members.length ? (
                  <tr>
                    <td colSpan={4} className="px-4 py-6 text-center text-muted-foreground">
                      Aucun membre.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
