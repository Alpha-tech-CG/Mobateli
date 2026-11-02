"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { api, setToken, ApiError } from "@/lib/api";
import { AuthShell, AuthField, AuthSubmit, authInput } from "@/components/auth-shell";

export default function SignupPage() {
  const router = useRouter();
  const [form, setForm] = useState({ name: "", organizationName: "", email: "", password: "" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm({ ...form, [k]: e.target.value });

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ token: string }>("/api/v1/auth/signup", {
        method: "POST",
        body: JSON.stringify(form),
      });
      setToken(res.token);
      router.replace("/dashboard");
    } catch (err) {
      const code = err instanceof ApiError ? err.code : "";
      if (code === "email_taken") {
        setError("Un compte existe déjà avec cet email. Connectez-vous plutôt.");
      } else if (code === "validation_error") {
        setError("Vérifiez les champs : le mot de passe doit faire au moins 12 caractères.");
      } else {
        setError("Création du compte impossible pour le moment. Réessayez dans un instant.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Créer un compte"
      subtitle="Faites auditer votre code généré par IA en quelques minutes."
      footer={
        <>
          Déjà un compte ?{" "}
          <Link href="/login" className="text-white underline-offset-4 hover:underline">
            Se connecter
          </Link>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-4">
        <AuthField label="Votre nom">
          <input required autoComplete="name" value={form.name} onChange={set("name")} className={authInput} />
        </AuthField>
        <AuthField label="Organisation" hint="Votre entreprise, agence ou projet.">
          <input
            required
            autoComplete="organization"
            value={form.organizationName}
            onChange={set("organizationName")}
            className={authInput}
          />
        </AuthField>
        <AuthField label="Email">
          <input type="email" required autoComplete="email" value={form.email} onChange={set("email")} className={authInput} />
        </AuthField>
        <AuthField label="Mot de passe" hint="12 caractères minimum.">
          <input
            type="password"
            required
            minLength={12}
            autoComplete="new-password"
            value={form.password}
            onChange={set("password")}
            className={authInput}
          />
        </AuthField>
        {error ? <p className="text-[13px] text-[#e8836f]">{error}</p> : null}
        <AuthSubmit busy={busy}>{busy ? "Création…" : "Créer mon compte"}</AuthSubmit>
      </form>
    </AuthShell>
  );
}
