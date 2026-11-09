"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card, KpiCard } from "@/components/ui";
import type { Member, Organization, Policy, RuleQualityReport } from "@/lib/types";

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
  const [quality, setQuality] = useState<RuleQualityReport | null>(null);
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
    // Pilot metric — optional: the overview still renders without it.
    api<RuleQualityReport>("/api/v1/metrics/rule-quality?days=30")
      .then(setQuality)
      .catch(() => setQuality(null));
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
            Fiabilité des alertes — 30 jours
          </h2>
          <div className="mb-3 grid grid-cols-1 gap-4 sm:grid-cols-3">
            <KpiCard label="Alertes" value={quality?.alerts ?? "—"} />
            <KpiCard label="Qualifiées" value={quality?.reviewed ?? "—"} hint="fausse alerte ou confirmée" />
            <KpiCard
              label="Taux de fausses alertes"
              value={quality?.falsePositiveRate == null ? "—" : `${Math.round(quality.falsePositiveRate * 100)} %`}
              hint="sur les alertes qualifiées"
            />
          </div>
          <Card>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="px-4 py-2 font-medium">Règle</th>
                  <th className="px-4 py-2 font-medium">Alertes</th>
                  <th className="px-4 py-2 font-medium">Fausses</th>
                  <th className="px-4 py-2 font-medium">Confirmées</th>
                  <th className="px-4 py-2 font-medium">Taux de fausses</th>
                </tr>
              </thead>
              <tbody>
                {(quality?.rules ?? []).map((r) => (
                  <tr key={r.ruleId} className="border-b border-border last:border-0 hover:bg-muted/50">
                    <td className="px-4 py-2 font-mono text-xs">{r.ruleId}</td>
                    <td className="px-4 py-2">{r.alerts}</td>
                    <td className="px-4 py-2">{r.falsePositives}</td>
                    <td className="px-4 py-2">{r.confirmed}</td>
                    <td className="px-4 py-2">
                      {r.falsePositiveRate == null ? "—" : `${Math.round(r.falsePositiveRate * 100)} %`}
                    </td>
                  </tr>
                ))}
                {!quality?.rules.length ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-6 text-center text-muted-foreground">
                      Aucune alerte sur la période.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </Card>

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
