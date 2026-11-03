"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowLeft } from "lucide-react";
import { api } from "@/lib/api";
import { Shell } from "@/components/shell";
import { ReportButton } from "@/components/report-button";
import { Card, SeverityBadge } from "@/components/ui";
import { ScoreBadge } from "@/components/score";
import { AgentInstall } from "@/components/agent-install";
import type { InfraCategory, ServerDetail } from "@/lib/types";

const CATEGORY_LABEL: Record<InfraCategory, string> = {
  ports: "Ports & services",
  ssh: "SSH",
  firewall: "Firewall",
  bruteforce: "Brute force",
  docker: "Docker",
  updates: "Mises à jour",
  backups: "Sauvegardes",
  tls: "TLS",
};

export default function ServerPage() {
  return (
    <Shell>
      <ServerView />
    </Shell>
  );
}

function ServerView() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [server, setServer] = useState<ServerDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    api<{ server: ServerDetail }>(`/api/v1/servers/${id}`)
      .then((r) => setServer(r.server))
      .catch(() => setError("Serveur introuvable."));
  }, [id]);

  async function rotate() {
    if (!confirm("Révoquer le token actuel ? L'agent devra être reconfiguré.")) return;
    const r = await api<{ agentToken: string }>(`/api/v1/servers/${id}/rotate-token`, {
      method: "POST",
    });
    setToken(r.agentToken);
  }

  async function remove() {
    if (!confirm("Retirer ce serveur de CodeGate ? Son historique d'audit sera supprimé.")) return;
    await api(`/api/v1/servers/${id}`, { method: "DELETE" });
    router.push("/servers");
  }

  if (error) return <Card className="p-4 text-sm text-destructive">{error}</Card>;
  if (!server) return <p className="text-sm text-muted-foreground">Chargement…</p>;

  const publicPorts = (server.lastReport?.listening ?? []).filter(
    (l) => l.proto === "tcp" && !/^(127\.|::1$|localhost$)/.test(l.address),
  );

  return (
    <div className="space-y-6">
      <Link
        href="/servers"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> Serveurs
      </Link>

      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-3 text-xl font-semibold">
            {server.name} <ScoreBadge score={server.securityScore} />
          </h1>
          <p className="font-mono text-xs text-muted-foreground">
            {server.hostname ?? "agent non installé"}
            {server.os ? ` · ${server.os}` : ""} · {server.environment}
            {server.agentVersion ? ` · agent ${server.agentVersion}` : ""}
            {server.lastReportAt
              ? ` · audité le ${new Date(server.lastReportAt).toLocaleString("fr-FR")}`
              : ""}
          </p>
        </div>
        <div className="flex items-start gap-2">
          <ReportButton type="server" id={server.id} name={server.name} />
          <button
            onClick={rotate}
            className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm transition-colors duration-150 hover:bg-muted"
          >
            Nouveau token
          </button>
          <button
            onClick={remove}
            className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm text-destructive transition-colors duration-150 hover:bg-muted"
          >
            Retirer
          </button>
        </div>
      </header>

      {token ? (
        <Card className="p-4">
          <AgentInstall token={token} />
        </Card>
      ) : null}

      {!server.lastReportAt && !token ? (
        <Card className="p-4 text-sm text-muted-foreground">
          En attente du premier rapport de l&apos;agent. Si vous avez perdu le token, générez-en
          un nouveau.
        </Card>
      ) : null}

      {server.lastReportAt ? (
        <>
          <section className="space-y-3">
            <h2 className="text-sm font-semibold">
              Points à corriger ({server.findings.length})
            </h2>
            {server.findings.length === 0 ? (
              <Card className="p-4 text-sm text-success">
                Aucun problème détecté sur les contrôles Infra Shield.
              </Card>
            ) : (
              server.findings.map((f) => (
                <Card key={f.id} className="p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <span className="text-xs uppercase tracking-wide text-muted-foreground">
                      {CATEGORY_LABEL[f.category]}
                    </span>
                  </div>
                  <p className="mt-2 font-medium">{f.title}</p>
                  <p className="mt-1 text-sm text-muted-foreground">{f.detail}</p>
                  <p className="mt-2 text-sm">
                    <span className="font-medium">Correctif : </span>
                    <Recommendation text={f.recommendation} />
                  </p>
                </Card>
              ))
            )}
          </section>

          <section className="space-y-3">
            <h2 className="text-sm font-semibold">Ports joignables depuis le réseau</h2>
            <Card>
              <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2 font-medium">Port</th>
                    <th className="px-4 py-2 font-medium">Adresse</th>
                    <th className="px-4 py-2 font-medium">Processus</th>
                  </tr>
                </thead>
                <tbody>
                  {publicPorts.map((l) => (
                    <tr key={`${l.address}:${l.port}`} className="border-b border-border last:border-0">
                      <td className="px-4 py-2 font-mono text-xs">{l.port}/tcp</td>
                      <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{l.address}</td>
                      <td className="px-4 py-2 font-mono text-xs">{l.process ?? "—"}</td>
                    </tr>
                  ))}
                  {!publicPorts.length ? (
                    <tr>
                      <td colSpan={3} className="px-4 py-6 text-center text-muted-foreground">
                        Aucun port TCP public.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
          </div>
            </Card>
          </section>
        </>
      ) : null}
    </div>
  );
}

/** Render `inline code` spans of a recommendation as monospace. */
function Recommendation({ text }: { text: string }) {
  return (
    <>
      {text.split(/(`[^`]+`)/).map((part, i) =>
        part.startsWith("`") ? (
          <code key={i} className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
            {part.slice(1, -1)}
          </code>
        ) : (
          <span key={i}>{part}</span>
        ),
      )}
    </>
  );
}
