"use client";

import { useEffect, useState, type FormEvent } from "react";
import QRCode from "qrcode";
import { CheckCircle2 } from "lucide-react";
import { api, ApiError, getSession, setToken } from "@/lib/api";
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

      <Card className="p-5 text-sm text-muted-foreground">
        Les sessions expirent au bout de 12 heures. Après 5 mots de passe erronés en 10 minutes,
        le compte est verrouillé temporairement ; après 3 codes MFA erronés, le second facteur est
        bloqué 5 minutes.
      </Card>
    </div>
  );
}
