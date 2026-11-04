"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";

export default function AccountPage() {
  return (
    <Shell>
      <Account />
    </Shell>
  );
}

function Account() {
  const [currentPassword, setCurrent] = useState("");
  const [newPassword, setNew] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (newPassword !== confirm) {
      setMessage({ ok: false, text: "Les deux nouveaux mots de passe ne correspondent pas." });
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      await api("/api/v1/auth/password", {
        method: "POST",
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      setCurrent("");
      setNew("");
      setConfirm("");
      setMessage({ ok: true, text: "Mot de passe modifié." });
    } catch (err) {
      const code = err instanceof ApiError ? err.code : "";
      setMessage({
        ok: false,
        text:
          code === "invalid_credentials"
            ? "Mot de passe actuel incorrect."
            : code === "validation_error"
              ? "Le nouveau mot de passe doit faire au moins 12 caractères et différer de l'actuel."
              : "Modification impossible.",
      });
    } finally {
      setBusy(false);
    }
  }

  const input =
    "w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring";

  return (
    <div>
      <header className="mb-6">
        <h1 className="text-xl font-semibold">Mon compte</h1>
        <p className="text-sm text-muted-foreground">Changez votre mot de passe.</p>
      </header>

      <Card className="max-w-md p-5">
        <form onSubmit={submit} className="space-y-4">
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">
              Mot de passe actuel
            </span>
            <input
              type="password"
              required
              autoComplete="current-password"
              value={currentPassword}
              onChange={(e) => setCurrent(e.target.value)}
              className={input}
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">
              Nouveau mot de passe (12 caractères minimum)
            </span>
            <input
              type="password"
              required
              minLength={12}
              autoComplete="new-password"
              value={newPassword}
              onChange={(e) => setNew(e.target.value)}
              className={input}
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">
              Confirmer le nouveau mot de passe
            </span>
            <input
              type="password"
              required
              minLength={12}
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className={input}
            />
          </label>
          {message ? (
            <p className={`text-sm ${message.ok ? "text-success" : "text-destructive"}`} role="status">
              {message.text}
            </p>
          ) : null}
          <button
            type="submit"
            disabled={busy}
            className="cursor-pointer rounded-md bg-primary px-4 py-2 text-sm font-medium text-on-primary hover:opacity-90 disabled:opacity-50"
          >
            {busy ? "Enregistrement…" : "Changer le mot de passe"}
          </button>
        </form>
      </Card>
    </div>
  );
}
