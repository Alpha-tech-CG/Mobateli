"use client";

import Link from "next/link";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { AuthShell, AuthField, AuthSubmit, authInput } from "@/components/auth-shell";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("/api/v1/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }) });
      setSent(true);
    } catch (err) {
      const code = err instanceof ApiError ? err.code : "";
      setError(
        code === "too_many_attempts"
          ? "Trop de demandes depuis cette connexion. Réessayez plus tard."
          : code === "validation_error"
            ? "Adresse email invalide."
            : "Envoi impossible pour le moment. Réessayez dans un instant.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Mot de passe oublié"
      subtitle="Recevez un lien pour choisir un nouveau mot de passe."
      footer={
        <Link href="/login" className="text-white underline-offset-4 hover:underline">
          Retour à la connexion
        </Link>
      }
    >
      {sent ? (
        <div className="space-y-3 text-[14px] text-[#c4c9cc]" role="status">
          <p>
            Si un compte existe pour <span className="text-white">{email}</span>, un email vient d&apos;être envoyé avec
            un lien de réinitialisation valable <strong className="text-white">1 heure</strong>.
          </p>
          <p className="text-[13px] text-[#9aa3a8]">Pensez à vérifier vos courriers indésirables.</p>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <AuthField label="Email du compte">
            <input
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className={authInput}
            />
          </AuthField>
          {error ? <p className="text-[13px] text-[#e8836f]">{error}</p> : null}
          <AuthSubmit busy={busy}>{busy ? "Envoi…" : "Envoyer le lien"}</AuthSubmit>
        </form>
      )}
    </AuthShell>
  );
}
