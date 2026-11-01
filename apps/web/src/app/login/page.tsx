"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { api, setToken, ApiError } from "@/lib/api";
import { Card } from "@/components/ui";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [mfa, setMfa] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const body = { email, password, ...(mfa && totp ? { totp } : {}) };
      const res = await api<{ token: string }>("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify(body),
      });
      setToken(res.token);
      router.replace("/");
    } catch (err) {
      if (err instanceof ApiError && err.code === "mfa_required") {
        setMfa(true);
        setError("Saisissez votre code à 6 chiffres.");
      } else if (err instanceof ApiError && err.code === "invalid_credentials") {
        setError("Identifiants invalides.");
      } else if (err instanceof ApiError && err.code === "invalid_totp") {
        setError("Code MFA invalide.");
      } else {
        setError("Connexion impossible. Vérifiez que l'API est démarrée.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <Card className="w-full max-w-sm p-6">
        <div className="mb-6 flex items-center gap-2">
          <ShieldCheck className="size-6 text-primary" aria-hidden />
          <span className="font-mono text-xl font-semibold">CodeGate</span>
        </div>
        <h1 className="mb-1 text-lg font-semibold">Connexion</h1>
        <p className="mb-5 text-sm text-muted-foreground">
          Sécurisez le code généré par IA avant la production.
        </p>
        <form onSubmit={submit} className="space-y-3">
          <Field label="Email">
            <input
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
            />
          </Field>
          <Field label="Mot de passe">
            <input
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
            />
          </Field>
          {mfa ? (
            <Field label="Code MFA">
              <input
                inputMode="numeric"
                pattern="\d{6}"
                value={totp}
                onChange={(e) => setTotp(e.target.value)}
                className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
              />
            </Field>
          ) : null}
          {error ? <p className="text-sm text-destructive">{error}</p> : null}
          <button
            type="submit"
            disabled={busy}
            className="w-full cursor-pointer rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary transition-colors duration-150 hover:opacity-90 disabled:opacity-50"
          >
            {busy ? "Connexion…" : "Se connecter"}
          </button>
        </form>
      </Card>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}
