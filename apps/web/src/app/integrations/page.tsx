"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, Plug, Bell } from "lucide-react";
import { api } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";

export default function IntegrationsPage() {
  return (
    <Shell>
      <Integrations />
    </Shell>
  );
}

function Integrations() {
  const [connected, setConnected] = useState(false);
  const [teamId, setTeamId] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [team, setTeam] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  function load() {
    api<{ connected: boolean; teamId: string | null }>("/api/v1/integrations/linear")
      .then((r) => {
        setConnected(r.connected);
        setTeamId(r.teamId);
      })
      .catch(() => setMsg("Impossible de charger le statut."));
  }
  useEffect(load, []);

  async function connect(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      await api("/api/v1/integrations/linear", {
        method: "POST",
        body: JSON.stringify({ apiKey, teamId: team }),
      });
      setApiKey("");
      setTeam("");
      setMsg("Linear connecté.");
      load();
    } catch {
      setMsg("Connexion impossible (clé invalide ou droits insuffisants).");
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    setBusy(true);
    try {
      await api("/api/v1/integrations/linear", { method: "DELETE" });
      load();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <header className="mb-6">
        <h1 className="text-xl font-semibold">Intégrations</h1>
        <p className="text-sm text-muted-foreground">
          Connectez vos outils pour la remédiation et le déploiement.
        </p>
      </header>

      <Card className="max-w-xl p-5">
        <div className="mb-4 flex items-center gap-3">
          <Plug className="size-5 text-primary" aria-hidden />
          <div>
            <h2 className="font-semibold">Linear</h2>
            <p className="text-xs text-muted-foreground">
              Crée automatiquement une issue de remédiation quand un risque bloquant est détecté.
            </p>
          </div>
        </div>

        {connected ? (
          <div className="space-y-3">
            <p className="flex items-center gap-2 text-sm text-success">
              <CheckCircle2 className="size-4" aria-hidden />
              Connecté — équipe <span className="font-mono">{teamId}</span>
            </p>
            <button
              onClick={disconnect}
              disabled={busy}
              className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm text-destructive transition-colors duration-150 hover:bg-muted disabled:opacity-50"
            >
              Déconnecter
            </button>
          </div>
        ) : (
          <form onSubmit={connect} className="space-y-3">
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">
                Clé API Linear
              </span>
              <input
                type="password"
                required
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="lin_api_…"
                className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">
                Team ID
              </span>
              <input
                required
                value={team}
                onChange={(e) => setTeam(e.target.value)}
                className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
              />
            </label>
            <button
              type="submit"
              disabled={busy}
              className="cursor-pointer rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary transition-colors duration-150 hover:opacity-90 disabled:opacity-50"
            >
              {busy ? "Connexion…" : "Connecter Linear"}
            </button>
          </form>
        )}
        {msg ? <p className="mt-3 text-sm text-muted-foreground">{msg}</p> : null}
      </Card>

      <SlackCard />
    </div>
  );
}

function SlackCard() {
  const [connected, setConnected] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  function load() {
    api<{ connected: boolean }>("/api/v1/integrations/slack")
      .then((r) => setConnected(r.connected))
      .catch(() => {});
  }
  useEffect(load, []);

  async function connect(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      await api("/api/v1/integrations/slack", {
        method: "POST",
        body: JSON.stringify({ webhookUrl }),
      });
      setWebhookUrl("");
      setMsg("Slack connecté.");
      load();
    } catch {
      setMsg("Connexion impossible (URL invalide ou droits insuffisants).");
    } finally {
      setBusy(false);
    }
  }

  async function test() {
    setBusy(true);
    setMsg(null);
    try {
      await api("/api/v1/integrations/slack/test", { method: "POST" });
      setMsg("Alerte de test envoyée.");
    } catch {
      setMsg("Envoi de test impossible.");
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    setBusy(true);
    try {
      await api("/api/v1/integrations/slack", { method: "DELETE" });
      load();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="mt-6 max-w-xl p-5">
      <div className="mb-4 flex items-center gap-3">
        <Bell className="size-5 text-primary" aria-hidden />
        <div>
          <h2 className="font-semibold">Slack</h2>
          <p className="text-xs text-muted-foreground">
            Alerte le canal en cas de PR bloquée, de secret détecté ou de déploiement bloqué.
          </p>
        </div>
      </div>

      {connected ? (
        <div className="space-y-3">
          <p className="flex items-center gap-2 text-sm text-success">
            <CheckCircle2 className="size-4" aria-hidden />
            Connecté
          </p>
          <div className="flex gap-2">
            <button
              onClick={test}
              disabled={busy}
              className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm transition-colors duration-150 hover:bg-muted disabled:opacity-50"
            >
              Envoyer un test
            </button>
            <button
              onClick={disconnect}
              disabled={busy}
              className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm text-destructive transition-colors duration-150 hover:bg-muted disabled:opacity-50"
            >
              Déconnecter
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={connect} className="space-y-3">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">
              URL du webhook entrant Slack
            </span>
            <input
              type="url"
              required
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/…"
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
            />
          </label>
          <button
            type="submit"
            disabled={busy}
            className="cursor-pointer rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary transition-colors duration-150 hover:opacity-90 disabled:opacity-50"
          >
            {busy ? "Connexion…" : "Connecter Slack"}
          </button>
        </form>
      )}
      {msg ? <p className="mt-3 text-sm text-muted-foreground">{msg}</p> : null}
    </Card>
  );
}
