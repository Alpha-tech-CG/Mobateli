"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { api, ApiError, setToken } from "@/lib/api";
import { useLinkToken } from "@/lib/link-token";
import { AuthShell, AuthField, AuthSubmit, authInput } from "@/components/auth-shell";

export default function AcceptInvitePage() {
  const router = useRouter();
  const token = useLinkToken();
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
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
      const res = await api<{ token: string }>("/api/v1/auth/accept-invite", {
        method: "POST",
        body: JSON.stringify({ token, password, ...(name.trim() ? { name: name.trim() } : {}) }),
      });
      setToken(res.token);
      router.replace("/dashboard");
    } catch (err) {
      const code = err instanceof ApiError ? err.code : "";
      setError(
        code === "invalid_or_expired_token"
          ? "Cette invitation est invalide, déjà utilisée ou expirée. Demandez-en une nouvelle à votre administrateur."
          : code === "account_disabled"
            ? "Ce compte a été désactivé par votre organisation."
            : code === "validation_error"
              ? "Le mot de passe doit faire au moins 12 caractères."
              : "Activation impossible pour le moment.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Activer votre compte"
      subtitle="Vous avez été invité à rejoindre une organisation sur CodeGate."
      footer={
        <>
          Déjà activé ?{" "}
          <Link href="/login" className="text-white underline-offset-4 hover:underline">
            Se connecter
          </Link>
        </>
      }
    >
      {token === undefined ? null : token === null ? (
        <p className="text-[14px] text-[#e8836f]">Lien d&apos;invitation incomplet. Ouvrez le lien reçu par email.</p>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <AuthField label="Votre nom" hint="Facultatif.">
            <input autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} className={authInput} />
          </AuthField>
          <AuthField label="Mot de passe" hint="12 caractères minimum.">
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
          <AuthSubmit busy={busy}>{busy ? "Activation…" : "Activer mon compte"}</AuthSubmit>
        </form>
      )}
    </AuthShell>
  );
}
