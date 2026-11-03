"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, Plug, Bell, Gitlab, Github, Ticket, UserCog, KeyRound } from "lucide-react";
import { api, ApiError } from "@/lib/api";
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

      <GithubCard />

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
            <LinearWebhook />
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
      <ScimCard />
      <SamlCard />
    </div>
  );
}

function SamlCard() {
  const [connected, setConnected] = useState(false);
  const [urls, setUrls] = useState<{ metadataUrl: string; acsUrl: string } | null>(null);
  const [form, setForm] = useState({ idpEntityId: "", idpSsoUrl: "", idpCert: "" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  function load() {
    api<{ connected: boolean; metadataUrl: string; acsUrl: string }>("/api/v1/integrations/saml")
      .then((r) => {
        setConnected(r.connected);
        setUrls({ metadataUrl: r.metadataUrl, acsUrl: r.acsUrl });
      })
      .catch(() => {});
  }
  useEffect(load, []);

  async function connect(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      await api("/api/v1/integrations/saml", { method: "POST", body: JSON.stringify(form) });
      setForm({ idpEntityId: "", idpSsoUrl: "", idpCert: "" });
      setMsg("SAML configuré.");
      load();
    } catch {
      setMsg("Configuration impossible (champs ou droits).");
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    setBusy(true);
    try {
      await api("/api/v1/integrations/saml", { method: "DELETE" });
      load();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="mt-6 max-w-xl p-5">
      <div className="mb-4 flex items-center gap-3">
        <KeyRound className="size-5 text-primary" aria-hidden />
        <div>
          <h2 className="font-semibold">SAML (SSO)</h2>
          <p className="text-xs text-muted-foreground">
            Authentification unique via votre fournisseur d&apos;identité.
          </p>
        </div>
      </div>

      {urls ? (
        <div className="mb-3 space-y-1 rounded-md border border-border bg-muted px-3 py-2 text-xs">
          <p>
            <span className="text-muted-foreground">Metadata SP :</span>{" "}
            <code className="font-mono break-all">{urls.metadataUrl}</code>
          </p>
          <p>
            <span className="text-muted-foreground">ACS URL :</span>{" "}
            <code className="font-mono break-all">{urls.acsUrl}</code>
          </p>
        </div>
      ) : null}

      {connected ? (
        <div className="space-y-3">
          <p className="flex items-center gap-2 text-sm text-success">
            <CheckCircle2 className="size-4" aria-hidden />
            Configuré
          </p>
          <button
            onClick={disconnect}
            disabled={busy}
            className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm text-destructive transition-colors duration-150 hover:bg-muted disabled:opacity-50"
          >
            Supprimer la configuration
          </button>
        </div>
      ) : (
        <form onSubmit={connect} className="space-y-3">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">IdP Entity ID</span>
            <input
              required
              value={form.idpEntityId}
              onChange={(e) => setForm({ ...form, idpEntityId: e.target.value })}
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">IdP SSO URL</span>
            <input
              type="url"
              required
              value={form.idpSsoUrl}
              onChange={(e) => setForm({ ...form, idpSsoUrl: e.target.value })}
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">
              Certificat IdP (X.509)
            </span>
            <textarea
              required
              rows={4}
              value={form.idpCert}
              onChange={(e) => setForm({ ...form, idpCert: e.target.value })}
              placeholder="MIIC…"
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs outline-none focus:ring-2 focus:ring-ring"
            />
          </label>
          <button
            type="submit"
            disabled={busy}
            className="cursor-pointer rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary transition-colors duration-150 hover:opacity-90 disabled:opacity-50"
          >
            {busy ? "Enregistrement…" : "Configurer SAML"}
          </button>
        </form>
      )}
      {msg ? <p className="mt-3 text-sm text-muted-foreground">{msg}</p> : null}
    </Card>
  );
}

function ScimCard() {
  const [connected, setConnected] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function load() {
    api<{ connected: boolean }>("/api/v1/integrations/scim")
      .then((r) => setConnected(r.connected))
      .catch(() => {});
  }
  useEffect(load, []);

  async function generate() {
    setBusy(true);
    try {
      const r = await api<{ token: string }>("/api/v1/integrations/scim", { method: "POST" });
      setToken(r.token);
      setConnected(true);
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    setBusy(true);
    try {
      await api("/api/v1/integrations/scim", { method: "DELETE" });
      setToken(null);
      load();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="mt-6 max-w-xl p-5">
      <div className="mb-4 flex items-center gap-3">
        <UserCog className="size-5 text-primary" aria-hidden />
        <div>
          <h2 className="font-semibold">SCIM (provisioning SSO)</h2>
          <p className="text-xs text-muted-foreground">
            Provisionnez les utilisateurs depuis votre IdP (Okta, Entra ID…). Endpoint :
            <code className="font-mono"> /scim/v2</code>
          </p>
        </div>
      </div>

      {token ? (
        <div className="space-y-2">
          <p className="text-sm">Jeton bearer SCIM (à coller dans la config de l'IdP) :</p>
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
            Activé
          </p>
          <div className="flex gap-2">
            <button
              onClick={generate}
              disabled={busy}
              className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm transition-colors duration-150 hover:bg-muted disabled:opacity-50"
            >
              Régénérer le jeton
            </button>
            <button
              onClick={disconnect}
              disabled={busy}
              className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm text-destructive transition-colors duration-150 hover:bg-muted disabled:opacity-50"
            >
              Désactiver
            </button>
          </div>
        </div>
      ) : (
        <button
          onClick={generate}
          disabled={busy}
          className="cursor-pointer rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary transition-colors duration-150 hover:opacity-90 disabled:opacity-50"
        >
          {busy ? "Génération…" : "Activer SCIM"}
        </button>
      )}
    </Card>
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
          <GitlabApiForm />
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

interface GithubInstallationRow {
  id: string;
  installationId: number;
  accountLogin: string;
  repositories: number;
  createdAt: string;
}

/** US01 — install the CodeGate GitHub App, choose repositories, revoke anytime. */
function GithubCard() {
  const [configured, setConfigured] = useState(true);
  const [rows, setRows] = useState<GithubInstallationRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  function load() {
    api<{ configured: boolean; installations: GithubInstallationRow[] }>("/api/v1/github/installations")
      .then((r) => {
        setConfigured(r.configured);
        setRows(r.installations);
      })
      .catch(() => setMsg("Impossible de charger GitHub."));
  }
  useEffect(load, []);

  async function connect() {
    setBusy(true);
    setMsg(null);
    try {
      const { url } = await api<{ url: string }>("/api/v1/github/install-url");
      window.location.href = url;
    } catch (err) {
      setMsg(
        err instanceof ApiError && err.code === "mfa_enrollment_required"
          ? "Activez d'abord la MFA (Sécurité du compte)."
          : "Connexion GitHub impossible pour le moment.",
      );
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    if (!confirm("Désinstaller CodeGate de ce compte GitHub ? Les PR ne seront plus analysées.")) return;
    await api(`/api/v1/github/installations/${id}`, { method: "DELETE" });
    load();
  }

  return (
    <Card className="mb-6 max-w-xl p-5">
      <div className="mb-3 flex items-center gap-3">
        <Github className="size-5" aria-hidden />
        <h2 className="font-medium">GitHub</h2>
        {rows.length ? <CheckCircle2 className="size-4 text-success" aria-label="connecté" /> : null}
      </div>
      <p className="mb-4 text-sm text-muted-foreground">
        Installez l&apos;application CodeGate et choisissez les dépôts : chaque pull request reçoit un
        check et un commentaire de sécurité. Permissions minimales, révocables à tout moment.
      </p>
      {rows.map((r) => (
        <div
          key={r.id}
          className="mb-3 flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm"
        >
          <span>
            <span className="font-medium">{r.accountLogin}</span>{" "}
            <span className="text-xs text-muted-foreground">
              · {r.repositories} dépôt{r.repositories > 1 ? "s" : ""}
            </span>
          </span>
          <button
            type="button"
            onClick={() => revoke(r.id)}
            className="cursor-pointer text-xs text-destructive hover:underline"
          >
            Révoquer
          </button>
        </div>
      ))}
      {configured ? (
        <button
          type="button"
          onClick={connect}
          disabled={busy}
          className="cursor-pointer rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary transition-colors duration-150 hover:opacity-90 disabled:opacity-50"
        >
          {rows.length ? "Ajouter un compte / des dépôts" : "Connecter GitHub"}
        </button>
      ) : (
        <p className="text-xs text-muted-foreground">
          L&apos;application GitHub n&apos;est pas encore créée pour ce CodeGate.{" "}
          <a href="/settings/github-app" className="text-primary hover:underline">
            Créer l&apos;App GitHub
          </a>
        </p>
      )}
      {msg ? <p className="mt-3 text-sm text-destructive">{msg}</p> : null}
    </Card>
  );
}

/** Linear → CodeGate webhook: issues closed in Linear resolve the findings. */
function LinearWebhook() {
  const [cfg, setCfg] = useState<{ url: string; secret: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function configure() {
    setErr(null);
    try {
      setCfg(await api<{ url: string; secret: string }>("/api/v1/integrations/linear/webhook", { method: "POST" }));
    } catch {
      setErr("Configuration impossible.");
    }
  }

  if (cfg) {
    return (
      <div className="space-y-2 rounded-md border border-border p-3 text-xs">
        <p>
          Dans Linear : Settings → API → Webhooks → « New webhook », événement <strong>Issues</strong>.
          Le secret ne sera plus affiché.
        </p>
        <p className="text-muted-foreground">URL</p>
        <pre className="overflow-x-auto rounded bg-muted p-2 font-mono">{cfg.url}</pre>
        <p className="text-muted-foreground">Secret de signature</p>
        <pre className="overflow-x-auto rounded bg-muted p-2 font-mono">{cfg.secret}</pre>
      </div>
    );
  }
  return (
    <div>
      <button
        type="button"
        onClick={configure}
        className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm transition-colors duration-150 hover:bg-muted"
      >
        Synchroniser les statuts depuis Linear
      </button>
      <p className="mt-1 text-xs text-muted-foreground">
        Une issue terminée dans Linear marque les problèmes de la PR comme résolus.
      </p>
      {err ? <p className="mt-1 text-xs text-destructive">{err}</p> : null}
    </div>
  );
}

/** GitLab API access: diffs of MRs + commit status and note feedback. */
function GitlabApiForm() {
  const [status, setStatus] = useState<{ apiConfigured: boolean; baseUrl: string | null } | null>(null);
  const [baseUrl, setBaseUrl] = useState("https://gitlab.com");
  const [token, setToken] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<{ apiConfigured: boolean; baseUrl: string | null }>("/api/v1/integrations/gitlab")
      .then((r) => {
        setStatus(r);
        if (r.baseUrl) setBaseUrl(r.baseUrl);
      })
      .catch(() => {});
  }, []);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const r = await api<{ apiConfigured: boolean; baseUrl: string }>("/api/v1/integrations/gitlab/api", {
        method: "PUT",
        body: JSON.stringify({ baseUrl, accessToken: token }),
      });
      setStatus(r);
      setToken("");
    } catch (err) {
      setMsg(
        err instanceof ApiError && err.code === "gitlab_token_invalid"
          ? "Jeton refusé par GitLab (portée « api » requise)."
          : err instanceof ApiError && err.code === "private_address"
            ? "Instance GitLab sur un réseau privé : non joignable depuis CodeGate."
            : "Enregistrement impossible.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={save} className="space-y-2 rounded-md border border-border p-3">
      <p className="text-xs text-muted-foreground">
        {status?.apiConfigured
          ? `Accès API actif (${status.baseUrl}) : diff des MR, statut « CodeGate » et commentaire publiés.`
          : "Ajoutez un jeton d'accès (portée « api ») pour analyser le code des MR et publier le résultat dans GitLab."}
      </p>
      <input
        value={baseUrl}
        onChange={(e) => setBaseUrl(e.target.value)}
        className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
      />
      <input
        type="password"
        required
        value={token}
        onChange={(e) => setToken(e.target.value)}
        placeholder="glpat-…"
        className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
      />
      <button
        type="submit"
        disabled={busy}
        className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm hover:bg-muted disabled:opacity-50"
      >
        {status?.apiConfigured ? "Remplacer le jeton" : "Enregistrer l'accès API"}
      </button>
      {msg ? <p className="text-xs text-destructive">{msg}</p> : null}
    </form>
  );
}
