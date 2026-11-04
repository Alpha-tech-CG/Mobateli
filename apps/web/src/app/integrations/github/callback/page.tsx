"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";

const ERRORS: Record<string, string> = {
  invalid_state: "Le lien d'installation a expiré ou ne correspond pas à votre organisation. Recommencez depuis Intégrations.",
  installation_linked_elsewhere: "Cette installation GitHub est déjà reliée à une autre organisation CodeGate.",
  installation_not_found: "Installation introuvable côté GitHub.",
  mfa_enrollment_required: "Activez d'abord la MFA (Sécurité du compte).",
  installation_not_authorized:
    "Votre compte GitHub n'a pas accès à cette installation : liaison refusée.",
  oauth_code_required:
    "GitHub n'a pas renvoyé d'autorisation. Dans les réglages de l'App, cochez « Request user authorization (OAuth) during installation », puis recommencez.",
  github_unreachable: "GitHub est injoignable. Réessayez dans un instant.",
};

/** GitHub sends the user back here after installing the App (Setup URL). */
export default function GithubCallbackPage() {
  return (
    <Shell>
      <Suspense fallback={null}>
        <Callback />
      </Suspense>
    </Shell>
  );
}

function Callback() {
  const params = useSearchParams();
  const router = useRouter();
  const [msg, setMsg] = useState("Liaison de l'installation GitHub…");
  const done = useRef(false);

  useEffect(() => {
    if (done.current) return;
    done.current = true;
    const installationId = params.get("installation_id");
    const state = params.get("state");
    // Present when the App asks for user authorization during installation:
    // lets the API verify this GitHub user can access the installation.
    const code = params.get("code");
    if (!installationId || !state) {
      setMsg("Paramètres GitHub manquants. Recommencez depuis Intégrations.");
      return;
    }
    api<{ accountLogin: string; repositories: number }>("/api/v1/github/link", {
      method: "POST",
      body: JSON.stringify({ installationId: Number(installationId), state, ...(code ? { code } : {}) }),
    })
      .then((r) => {
        setMsg(`GitHub connecté (${r.accountLogin}, ${r.repositories} dépôt(s)). Redirection…`);
        setTimeout(() => router.replace("/integrations"), 1500);
      })
      .catch((err) =>
        setMsg(err instanceof ApiError ? (ERRORS[err.code] ?? "Liaison impossible.") : "Liaison impossible."),
      );
  }, [params, router]);

  return <Card className="max-w-xl p-5 text-sm">{msg}</Card>;
}
