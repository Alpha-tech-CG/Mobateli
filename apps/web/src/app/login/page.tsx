"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { api, setToken, ApiError } from "@/lib/api";
import { AuthShell, AuthField, AuthSubmit, authInput } from "@/components/auth-shell";

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
      router.replace("/dashboard");
    } catch (err) {
      const code = err instanceof ApiError ? err.code : "";
      if (code === "mfa_required") {
        setMfa(true);
        setError("Saisissez le code à 6 chiffres de votre application d'authentification.");
      } else if (code === "invalid_credentials") {
        setError("Email ou mot de passe incorrect.");
      } else if (code === "invalid_totp") {
        setError("Code MFA invalide.");
      } else if (code === "account_disabled") {
        setError("Ce compte a été désactivé.");
      } else {
        setError("Connexion impossible pour le moment. Réessayez dans un instant.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Connexion"
      subtitle="Accédez à votre espace pour auditer votre code."
      footer={
        <>
          Pas encore de compte ?{" "}
          <Link href="/signup" className="text-white underline-offset-4 hover:underline">
            Créer un compte
          </Link>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-4">
        <AuthField label="Email">
          <input
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className={authInput}
          />
        </AuthField>
        <AuthField label="Mot de passe">
          <input
            type="password"
            required
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={authInput}
          />
        </AuthField>
        {mfa ? (
          <AuthField label="Code MFA">
            <input
              inputMode="numeric"
              pattern="\d{6}"
              autoComplete="one-time-code"
              value={totp}
              onChange={(e) => setTotp(e.target.value)}
              className={`${authInput} font-mono tracking-[0.3em]`}
            />
          </AuthField>
        ) : null}
        <p className="-mt-1 text-right text-[13px]">
          <Link href="/forgot-password" className="text-[#9aa3a8] underline-offset-4 hover:text-white hover:underline">
            Mot de passe oublié ?
          </Link>
        </p>
        {error ? <p className="text-[13px] text-[#e8836f]">{error}</p> : null}
        <AuthSubmit busy={busy}>{busy ? "Connexion…" : "Se connecter"}</AuthSubmit>
      </form>
    </AuthShell>
  );
}
