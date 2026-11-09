"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, ApiError, getSession } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";
import type { MemberRow, Role } from "@/lib/types";

const ROLES: { value: Role; label: string }[] = [
  { value: "owner", label: "Owner" },
  { value: "admin", label: "Admin" },
  { value: "security_manager", label: "Security Manager" },
  { value: "developer", label: "Developer" },
  { value: "auditor", label: "Auditor" },
  { value: "viewer", label: "Viewer" },
];

const ERRORS: Record<string, string> = {
  last_owner: "L'organisation doit garder au moins un owner actif.",
  owner_only: "Seul un owner peut modifier un owner ou attribuer ce rôle.",
  cannot_modify_self: "Vous ne pouvez pas modifier votre propre compte ici.",
  email_taken: "Cette adresse est déjà utilisée.",
  mfa_enrollment_required: "Activez d'abord la MFA (Sécurité du compte).",
  forbidden: "Rôle Owner ou Admin requis.",
};
const errorText = (err: unknown) =>
  err instanceof ApiError ? (ERRORS[err.code] ?? "Action impossible.") : "Action impossible.";

const inputClass =
  "rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring";

export default function MembersPage() {
  return (
    <Shell>
      <Members />
    </Shell>
  );
}

function Members() {
  const [members, setMembers] = useState<MemberRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [invite, setInvite] = useState({ email: "", role: "developer" as Role });
  const [tempPassword, setTempPassword] = useState<string | null>(null);
  const [invitedEmail, setInvitedEmail] = useState<string | null>(null);
  const session = getSession();
  const canManage = session?.role === "owner" || session?.role === "admin";

  const load = useCallback(() => {
    api<{ members: MemberRow[] }>("/api/v1/organization/members")
      .then((r) => setMembers(r.members))
      .catch(() => setError("Impossible de charger les membres."));
  }, []);
  useEffect(load, [load]);

  async function update(id: string, patch: { role?: Role; active?: boolean }) {
    setError(null);
    try {
      await api(`/api/v1/organization/members/${id}`, { method: "PATCH", body: JSON.stringify(patch) });
    } catch (err) {
      setError(errorText(err));
    }
    load();
  }

  async function sendInvite(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const r = await api<{ inviteSent: boolean; tempPassword?: string }>("/api/v1/organization/members", {
        method: "POST",
        body: JSON.stringify(invite),
      });
      if (r.inviteSent) setInvitedEmail(invite.email);
      else setTempPassword(r.tempPassword ?? null);
      setInvite({ email: "", role: "developer" });
      load();
    } catch (err) {
      setError(errorText(err));
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">Membres</h1>
        <p className="text-sm text-muted-foreground">
          Rôles à moindre privilège (cahier §12.1). Un membre désactivé ne peut plus se connecter
          ; l&apos;organisation garde toujours un owner actif.
        </p>
      </header>

      {error ? <Card className="p-4 text-sm text-destructive">{error}</Card> : null}

      {canManage ? (
        <Card className="p-4">
          <h2 className="mb-3 text-sm font-semibold">Inviter un membre</h2>
          {invitedEmail ? (
            <div className="space-y-2 text-sm" role="status">
              <p>
                Invitation envoyée à <span className="font-medium">{invitedEmail}</span>. Le lien d&apos;activation est
                valable 7 jours ; la personne choisira elle-même son mot de passe.
              </p>
              <button
                type="button"
                onClick={() => setInvitedEmail(null)}
                className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm hover:bg-muted"
              >
                Inviter quelqu&apos;un d&apos;autre
              </button>
            </div>
          ) : tempPassword ? (
            <div className="space-y-2 text-sm">
              <p>
                Compte créé. Transmettez ce mot de passe temporaire par un canal sûr ; il ne sera
                plus affiché :
              </p>
              <code className="block break-all rounded-md bg-muted px-3 py-2 font-mono text-xs">{tempPassword}</code>
              <button
                type="button"
                onClick={() => setTempPassword(null)}
                className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm hover:bg-muted"
              >
                C&apos;est noté
              </button>
            </div>
          ) : (
            <form onSubmit={sendInvite} className="flex flex-wrap gap-2">
              <input
                type="email"
                required
                value={invite.email}
                onChange={(e) => setInvite({ ...invite, email: e.target.value })}
                placeholder="prenom@entreprise.com"
                className={`${inputClass} min-w-[240px] flex-1`}
              />
              <select
                value={invite.role}
                onChange={(e) => setInvite({ ...invite, role: e.target.value as Role })}
                className={inputClass}
              >
                {ROLES.filter((r) => session?.role === "owner" || r.value !== "owner").map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </select>
              <button
                type="submit"
                className="cursor-pointer rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary hover:opacity-90"
              >
                Inviter
              </button>
            </form>
          )}
        </Card>
      ) : null}

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[620px] text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted-foreground">
                <th className="px-4 py-2 font-medium">Membre</th>
                <th className="px-4 py-2 font-medium">Rôle</th>
                <th className="px-4 py-2 font-medium">MFA</th>
                <th className="px-4 py-2 font-medium">Statut</th>
              </tr>
            </thead>
            <tbody>
              {members.map((m) => (
                <tr key={m.id} className={`border-b border-border last:border-0 ${m.active ? "" : "opacity-60"}`}>
                  <td className="px-4 py-2">
                    <div className="font-medium">{m.name}</div>
                    <div className="text-xs text-muted-foreground">{m.email}</div>
                  </td>
                  <td className="px-4 py-2">
                    {canManage ? (
                      <select
                        value={m.role}
                        onChange={(e) => update(m.id, { role: e.target.value as Role })}
                        className={`${inputClass} py-1`}
                      >
                        {ROLES.map((r) => (
                          <option key={r.value} value={r.value}>
                            {r.label}
                          </option>
                        ))}
                      </select>
                    ) : (
                      ROLES.find((r) => r.value === m.role)?.label
                    )}
                  </td>
                  <td className={`px-4 py-2 text-xs ${m.mfaEnabled ? "text-success" : "text-muted-foreground"}`}>
                    {m.mfaEnabled ? "activée" : "non"}
                  </td>
                  <td className="px-4 py-2 text-xs">
                    {canManage ? (
                      <button
                        type="button"
                        onClick={() => update(m.id, { active: !m.active })}
                        className={`cursor-pointer hover:underline ${m.active ? "text-destructive" : "text-primary"}`}
                      >
                        {m.active ? "Désactiver" : "Réactiver"}
                      </button>
                    ) : m.active ? (
                      "actif"
                    ) : (
                      "désactivé"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
