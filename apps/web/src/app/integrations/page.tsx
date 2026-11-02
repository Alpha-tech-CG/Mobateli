"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, Plug, Bell, Gitlab, Ticket } from "lucide-react";
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
      <GitlabCard />
      <JiraCard />
    </div>
  );
}

function JiraCard() {
  const [connected, setConnected] = useState(false);
  const [projectKey, setProjectKey] = useState<string | null>(null);
  const [form, setForm] = useState({ baseUrl: "", email: "", apiToken: "", projectKey: "" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  function load() {
    api<{ connected: boolean; projectKey: string | null }>("/api/v1/integrations/jira")
      .then((r) => {
        setConnected(r.connected);
        setProjectKey(r.projectKey);
      })
      .catch(() => {});
  }
  useEffect(load, []);

  async function connect(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      await api("/api/v1/integrations/jira", { method: "POST", body: JSON.stringify(form) });
      setForm({ baseUrl: "", email: "", apiToken: "", projectKey: "" });
      setMsg("Jira connecté.");
      load();
    } catch {
      setMsg("Connexion impossible (identifiants ou droits).");
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    setBusy(true);
    try {
      await api("/api/v1/integrations/jira", { method: "DELETE" });
      load();
    } finally {
      setBusy(false);
    }
  }

  const field = (key: keyof typeof form, label: string, type = "text", ph = "") => (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-muted-foreground">{label}</span>
      <input
        type={type}
        required
        value={form[key]}
        onChange={(e) => setForm({ ...form, [key]: e.target.value })}
        placeholder={ph}
        className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
      />
    </label>
  );

  return (
    <Card className="mt-6 max-w-xl p-5">
      <div className="mb-4 flex items-center gap-3">
        <Ticket className="size-5 text-primary" aria-hidden />
        <div>
          <h2 className="font-semibold">Jira</h2>
          <p className="text-xs text-muted-foreground">
            Crée une issue de remédiation Jira (entreprise) sur risque bloquant.
          </p>
        </div>
      </div>

      {connected ? (
        <div className="space-y-3">
          <p className="flex items-center gap-2 text-sm text-success">
            <CheckCircle2 className="size-4" aria-hidden />
            Connecté — projet <span className="font-mono">{projectKey}</span>
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
          {field("baseUrl", "URL Jira", "url", "https://votre-org.atlassian.net")}
          {field("email", "Email", "email", "vous@entreprise.com")}
          {field("apiToken", "Jeton API", "password", "jeton Atlassian")}
          {field("projectKey", "Clé de projet", "text", "SEC")}
          <button
            type="submit"
            disabled={busy}
            className="cursor-pointer rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary transition-colors duration-150 hover:opacity-90 disabled:opacity-50"
          >
            {busy ? "Connexion…" : "Connecter Jira"}
          </button>
        </form>
      )}
      {msg ? <p className="mt-3 text-sm text-muted-foreground">{msg}</p> : null}
    </Card>
  );
}

function GitlabCard() {
  const [connected, setConnected] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function load() {
    api<{ connected: boolean }>("/api/v1/integrations/gitlab")
      .then((r) => setConnected(r.connected))
      .catch(() => {});
  }
  useEffect(load, []);

  async function connect() {
    setBusy(true);
    try {
      const r = await api<{ webhookToken: string }>("/api/v1/integrations/gitlab", {
        method: "POST",
      });
      setToken(r.webhookToken);
      setConnected(true);
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    setBusy(true);
    try {
      await api("/api/v1/integrations/gitlab", { method: "DELETE" });
      setToken(null);
      load();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="mt-6 max-w-xl p-5">
      <div className="mb-4 flex items-center gap-3">
        <Gitlab className="size-5 text-primary" aria-hidden />
        <div>
          <h2 className="font-semibold">GitLab</h2>
          <p className="text-xs text-muted-foreground">
            Analyse les merge requests comme un 2ᵉ fournisseur SCM.
          </p>
        </div>
      </div>

      {token ? (
        <div className="space-y-2">
          <p className="text-sm">
            Collez ce <span className="font-medium">Secret token</span> dans le webhook GitLab
            (événement « Merge request »), URL <code className="font-mono">/webhooks/gitlab</code> :
          </p>
          <code className="block break-all rounded-md border border-border bg-muted px-3 py-2 font-mono text-xs">
            {token}
          </code>
          <p className="text-xs text-muted-foreground">
            Copiez-le maintenant — il ne sera plus affiché.
          </p>
        </div>
      ) : connected ? (
        <div className="space-y-3">
          <p className="flex items-center gap-2 text-sm text-success">
            <CheckCircle2 className="size-4" aria-hidden />
            Connecté
          </p>
          <div className="flex gap-2">
            <button
              onClick={connect}
              disabled={busy}
              className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm transition-colors duration-150 hover:bg-muted disabled:opacity-50"
            >
              Régénérer le token
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
        <button
          onClick={connect}
          disabled={busy}
          className="cursor-pointer rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary transition-colors duration-150 hover:opacity-90 disabled:opacity-50"
        >
          {busy ? "Génération…" : "Connecter GitLab"}
        </button>
      )}
    </Card>
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
