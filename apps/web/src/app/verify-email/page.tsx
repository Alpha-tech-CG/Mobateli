"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { api, ApiError, getToken } from "@/lib/api";
import { useLinkToken } from "@/lib/link-token";
import { AuthShell } from "@/components/auth-shell";

type State = "checking" | "verified" | "invalid" | "error";

export default function VerifyEmailPage() {
  const token = useLinkToken();
  const [state, setState] = useState<State>("checking");
  // The link is single use: submit it exactly once, even if the effect re-runs.
  const submitted = useRef(false);

  useEffect(() => {
    if (token === undefined) return;
    if (token === null) {
      setState("invalid");
      return;
    }
    if (submitted.current) return;
    submitted.current = true;
    api("/api/v1/auth/verify-email", { method: "POST", body: JSON.stringify({ token }) })
      .then(() => setState("verified"))
      .catch((err) => setState(err instanceof ApiError && err.code === "invalid_or_expired_token" ? "invalid" : "error"));
  }, [token]);

  const signedIn = typeof window !== "undefined" && !!getToken();
  const next = signedIn ? { href: "/dashboard", label: "Aller au tableau de bord" } : { href: "/login", label: "Se connecter" };

  return (
    <AuthShell
      title="Vérification de l'email"
      subtitle="Confirmation de votre adresse CodeGate."
      footer={
        <Link href={next.href} className="text-white underline-offset-4 hover:underline">
          {next.label}
        </Link>
      }
    >
      <div className="text-[14px] text-[#c4c9cc]" role="status" aria-live="polite">
        {state === "checking" ? <p>Vérification en cours…</p> : null}
        {state === "verified" ? <p className="text-white">Adresse confirmée. Votre compte est prêt.</p> : null}
        {state === "invalid" ? (
          <p className="text-[#e8836f]">
            Ce lien est invalide, déjà utilisé ou expiré. Connectez-vous puis demandez un nouveau lien depuis le bandeau
            en haut de l&apos;application.
          </p>
        ) : null}
        {state === "error" ? <p className="text-[#e8836f]">Vérification impossible pour le moment. Réessayez dans un instant.</p> : null}
      </div>
    </AuthShell>
  );
}
