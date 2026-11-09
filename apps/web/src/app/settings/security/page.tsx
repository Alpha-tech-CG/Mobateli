"use client";

import { useEffect, useState, type FormEvent } from "react";
import QRCode from "qrcode";
import { CheckCircle2 } from "lucide-react";
import { api, apiDownload, ApiError, clearToken, getSession, setToken } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";

export default function SecuritySettingsPage() {
  return (
    <Shell>
      <SecuritySettings />
    </Shell>
  );
}

function SecuritySettings() {
  const [enabled, setEnabled] = useState(false);
  const [otpauth, setOtpauth] = useState<string | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setEnabled(Boolean(getSession()?.mfa));
  }, []);

  useEffect(() => {
    if (!otpauth) return;
    void QRCode.toDataURL(otpauth, { margin: 1, width: 200 }).then(setQr);
  }, [otpauth]);

  async function start() {
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ otpauth: string }>("/api/v1/auth/mfa/setup", { method: "POST" });
      setOtpauth(r.otpauth);
    } catch {
      setError("Impossible de démarrer l'activation.");
    } finally {
      setBusy(false);
    }
  }

  async function verify(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ mfaEnabled: boolean; token?: string }>("/api/v1/auth/mfa/verify", {
        method: "POST",
        body: JSON.stringify({ totp: code.trim() }),
      });
      if (r.token) setToken(r.token);
      setEnabled(true);
      setOtpauth(null);
      // Reload so the shell drops the MFA banner with the new session.
      window.location.reload();
    } catch (err) {
      setError(
        err instanceof ApiError && err.code === "too_many_attempts"
          ? "Trop de codes invalides. Réessayez dans quelques minutes."
          : "Code invalide. Vérifiez l'heure de votre téléphone et réessayez.",
      );
    } finally {
      setBusy(false);
    }
  }

  const secret = otpauth ? new URL(otpauth).searchParams.get("secret") : null;

  return (
    <div className="max-w-xl space-y-6">
      <header>
        <h1 className="text-xl font-semibold">Sécurité du compte</h1>
        <p className="text-sm text-muted-foreground">
          Double authentification (TOTP) avec une application comme Google Authenticator, 1Password
          ou Microsoft Authenticator. Obligatoire pour les rôles Owner et Admin.
        </p>
      </header>

      <Card className="space-y-4 p-5">
        {enabled ? (
          <p className="flex items-center gap-2 text-sm text-success">
            <CheckCircle2 className="h-5 w-5" /> Double authentification active sur ce compte.
          </p>
        ) : otpauth ? (
          <form onSubmit={verify} className="space-y-4">
            <p className="text-sm">1. Scannez ce QR code avec votre application d&apos;authentification.</p>
            {qr ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img src={qr} alt="QR code MFA" className="rounded-md bg-white p-2" width={200} height={200} />
            ) : null}
            {secret ? (
              <p className="text-xs text-muted-foreground">
                Ou saisissez la clé : <code className="font-mono">{secret}</code>
              </p>
            ) : null}
            <label className="block">
              <span className="mb-1 block text-sm">2. Entrez le code à 6 chiffres affiché</span>
              <input
                required
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="\d{6}"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                className="w-40 rounded-md border border-border bg-background px-3 py-2 font-mono text-lg tracking-widest outline-none focus:ring-2 focus:ring-ring"
              />
            </label>
            {error ? <p className="text-sm text-destructive">{error}</p> : null}
            <button
              type="submit"
              disabled={busy}
              className="cursor-pointer rounded-md bg-primary px-4 py-2 text-sm font-medium text-on-primary hover:opacity-90 disabled:opacity-50"
            >
              Activer
            </button>
          </form>
        ) : (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">La double authentification n&apos;est pas activée.</p>
            {error ? <p className="text-sm text-destructive">{error}</p> : null}
            <button
              onClick={start}
              disabled={busy}
              className="cursor-pointer rounded-md bg-primary px-4 py-2 text-sm font-medium text-on-primary hover:opacity-90 disabled:opacity-50"
            >
              Configurer la MFA
            </button>
          </div>
        )}
      </Card>

      <PrivacyCard />

      <Card className="p-5 text-sm text-muted-foreground">
        Les sessions expirent au bout de 12 heures. Après 5 mots de passe erronés en 10 minutes,
        le compte est verrouillé temporairement ; après 3 codes MFA erronés, le second facteur est
        bloqué 5 minutes.
      </Card>
    </div>
  );
}

/** RGPD: data portability and the right to erasure (cahier §10.1, §11.3). */
function PrivacyCard() {
  const session = getSession();
  const isOwner = session?.role === "owner";
  const canExport = isOwner || session?.role === "admin";
  const [confirmName, setConfirmName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function exportData() {
    setError(null);
    try {
      await apiDownload("/api/v1/organization/export", null, "codegate-export.json");
    } catch {
      setError("Export impossible (rôle Owner ou Admin avec MFA requis).");
    }
  }

  async function erase(e: FormEvent) {
    e.preventDefault();
    if (!confirm("Supprimer définitivement l'organisation et toutes ses données ? Action irréversible.")) return;
    setBusy(true);
    setError(null);
    try {
      await api("/api/v1/organization", { method: "DELETE", body: JSON.stringify({ confirmName }) });
      clearToken();
      window.location.href = "/";
    } catch (err) {
      setError(
        err instanceof ApiError && err.code === "confirmation_mismatch"
          ? "Le nom saisi ne correspond pas exactement au nom de l'organisation."
          : "Suppression impossible.",
      );
      setBusy(false);
    }
  }

  return (
    <Card className="space-y-4 p-5">
      <div>
        <h2 className="font-medium">Vos données (RGPD)</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Hébergement UE. Analyses conservées 365 jours, journal d&apos;audit 730 jours. Aucune
          donnée n&apos;est utilisée pour entraîner un modèle.
        </p>
      </div>
      {canExport ? (
        <button
          type="button"
          onClick={exportData}
          className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm hover:bg-muted"
        >
          Exporter toutes les données (JSON)
        </button>
      ) : null}
      {isOwner ? (
        <form onSubmit={erase} className="space-y-2 border-t border-border pt-4">
          <p className="text-sm font-medium text-destructive">Supprimer l&apos;organisation</p>
          <p className="text-xs text-muted-foreground">
            Supprime définitivement les membres, dépôts, analyses, serveurs, sauvegardes suivies et
            le journal d&apos;audit. Saisissez le nom exact de l&apos;organisation pour confirmer.
          </p>
          <div className="flex flex-wrap gap-2">
            <input
              required
              value={confirmName}
              onChange={(e) => setConfirmName(e.target.value)}
              placeholder="Nom de l'organisation"
              className="w-64 rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
            />
            <button
              type="submit"
              disabled={busy}
              className="cursor-pointer rounded-md border border-destructive px-3 py-2 text-sm text-destructive hover:bg-destructive/10 disabled:opacity-50"
            >
              Supprimer définitivement
            </button>
          </div>
        </form>
      ) : null}
      {error ? <p className="text-sm text-destructive">{error}</p> : null}
    </Card>
  );
}
