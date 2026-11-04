"use client";

import Link from "next/link";
import { useState } from "react";
import { api, ApiError, clearToken } from "@/lib/api";
import { useLinkToken } from "@/lib/link-token";
import { AuthShell, AuthField, AuthSubmit, authInput } from "@/components/auth-shell";

export default function ResetPasswordPage() {
  const token = useLinkToken();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      setError("Les deux mots de passe ne correspondent pas.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api("/api/v1/auth/reset-password", { method: "POST", body: JSON.stringify({ token, password }) });
      clearToken(); // every session was revoked server-side
      setDone(true);
    } catch (err) {
      const code = err instanceof ApiError ? err.code : "";
      setError(
        code === "invalid_or_expired_token"
          ? "Ce lien est invalide, déjà utilisé ou expiré. Demandez-en un nouveau."
          : code === "validation_error"
            ? "Le mot de passe doit faire au moins 12 caractères."
            : code === "too_many_attempts"
              ? "Trop de tentatives. Réessayez plus tard."
              : "Réinitialisation impossible pour le moment.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Nouveau mot de passe"
      subtitle="Choisissez un mot de passe d'au moins 12 caractères."
      footer={
        <Link href="/forgot-password" className="text-white underline-offset-4 hover:underline">
          Demander un nouveau lien
        </Link>
      }
    >
      {token === undefined ? null : token === null ? (
        <p className="text-[14px] text-[#e8836f]">Lien incomplet. Ouvrez le lien reçu par email, ou demandez-en un nouveau.</p>
      ) : done ? (
        <div className="space-y-4 text-[14px] text-[#c4c9cc]" role="status">
          <p>Mot de passe modifié. Par sécurité, toutes les sessions ouvertes ont été déconnectées.</p>
          <Link
            href="/login"
            className="flex h-12 w-full items-center justify-center rounded-[40px] bg-[#bb3e2c] text-[14px] font-medium text-white hover:bg-[#a63523]"
          >
            Se connecter
          </Link>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <AuthField label="Nouveau mot de passe" hint="12 caractères minimum.">
            <input
              type="password"
              required
              minLength={12}
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={authInput}
            />
          </AuthField>
          <AuthField label="Confirmer le mot de passe">
            <input
              type="password"
              required
              minLength={12}
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className={authInput}
            />
          </AuthField>
          {error ? <p className="text-[13px] text-[#e8836f]">{error}</p> : null}
          <AuthSubmit busy={busy}>{busy ? "Enregistrement…" : "Changer le mot de passe"}</AuthSubmit>
        </form>
      )}
    </AuthShell>
  );
}
