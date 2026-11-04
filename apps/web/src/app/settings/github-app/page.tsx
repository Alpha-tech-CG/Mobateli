"use client";

import Link from "next/link";
import { Suspense, useEffect, useRef, useState, type FormEvent } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { CheckCircle2, Github } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";

interface Status {
  configured: boolean;
  source: "env" | "database" | null;
  slug: string | null;
  canConfigure: boolean;
}

const ERRORS: Record<string, string> = {
  platform_operator_only: "Réservé au propriétaire de cette installation de CodeGate.",
  configured_by_environment: "L'App est déjà définie par les variables d'environnement du serveur.",
  invalid_state: "Le lien de retour a expiré ou ne correspond pas. Recommencez.",
  manifest_code_invalid: "GitHub a refusé le code (il expire au bout d'une heure). Recommencez.",
  mfa_enrollment_required: "Activez d'abord la MFA (Sécurité du compte).",
  validation_error: "Nom invalide (3 à 34 caractères).",
};

export default function GithubAppPage() {
  return (
    <Shell>
      <Suspense fallback={null}>
        <GithubApp />
      </Suspense>
    </Shell>
  );
}

/** Operator page: create the deployment's GitHub App in one click (manifest flow). */
function GithubApp() {
  const params = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = useState<Status | null>(null);
  const [name, setName] = useState("CodeGate Security");
  const [org, setOrg] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const [manifest, setManifest] = useState<{ action: string; manifest: string } | null>(null);
  const completing = useRef(false);

  const load = () =>
    api<Status>("/api/v1/platform/github-app")
      .then(setStatus)
      .catch(() => setMsg("Impossible de charger l'état de l'App GitHub."));

  useEffect(() => {
    const code = params.get("code");
    const state = params.get("state");
    if (code && state && !completing.current) {
      completing.current = true;
      setMsg("Enregistrement de l'App créée sur GitHub…");
      api<{ slug: string; installUrl: string }>("/api/v1/platform/github-app/complete", {
        method: "POST",
        body: JSON.stringify({ code, state }),
      })
        .then((r) => {
          setMsg(`App « ${r.slug} » créée et enregistrée.`);
          router.replace("/settings/github-app");
          void load();
        })
        .catch((err) => setMsg(err instanceof ApiError ? (ERRORS[err.code] ?? "Enregistrement impossible.") : "Enregistrement impossible."));
    } else {
      void load();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // GitHub's manifest flow needs a real form POST from the browser.
  useEffect(() => {
    if (manifest) formRef.current?.submit();
  }, [manifest]);

  async function start(e: FormEvent) {
    e.preventDefault();
    setMsg(null);
    try {
      setManifest(
        await api<{ action: string; manifest: string }>("/api/v1/platform/github-app/manifest", {
          method: "POST",
          body: JSON.stringify({ name, ...(org.trim() ? { githubOrganization: org.trim() } : {}) }),
        }),
      );
    } catch (err) {
      setMsg(err instanceof ApiError ? (ERRORS[err.code] ?? "Création impossible.") : "Création impossible.");
    }
  }

  return (
    <div className="max-w-xl space-y-6">
      <header>
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <Github className="size-5" aria-hidden /> Application GitHub
        </h1>
        <p className="text-sm text-muted-foreground">
          L&apos;App GitHub de votre installation CodeGate : c&apos;est elle que vos équipes installent sur
          leurs dépôts pour faire analyser chaque pull request.
        </p>
      </header>

      {msg ? <Card className="p-4 text-sm">{msg}</Card> : null}

      {status?.configured ? (
        <Card className="space-y-3 p-5">
          <p className="flex items-center gap-2 text-sm text-success">
            <CheckCircle2 className="size-4" aria-hidden /> App configurée
            {status.slug ? (
              <>
                {" : "}
                <a href={`https://github.com/apps/${status.slug}`} target="_blank" rel="noopener noreferrer" className="font-mono underline">
                  {status.slug}
                </a>
              </>
            ) : null}
            <span className="text-xs text-muted-foreground">({status.source === "env" ? "variables d'environnement" : "créée depuis CodeGate"})</span>
          </p>
          <div className="flex flex-wrap gap-2">
            <Link href="/integrations" className="rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary hover:opacity-90">
              Connecter mes dépôts
            </Link>
          </div>
        </Card>
      ) : status && !status.canConfigure ? (
        <Card className="p-5 text-sm text-muted-foreground">
          L&apos;App GitHub n&apos;est pas encore configurée. Seul le propriétaire de cette installation
          de CodeGate peut la créer.
        </Card>
      ) : status ? (
        <Card className="p-5">
          <form onSubmit={start} className="space-y-3">
            <p className="text-sm">
              GitHub va créer l&apos;App avec des permissions minimales (lecture du code, écriture des
              checks et commentaires de PR) et renvoyer ses clés à CodeGate, qui les stocke
              chiffrées. Vous validez la création sur GitHub.
            </p>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">Nom public de l&apos;App (unique sur GitHub)</span>
              <input
                required
                minLength={3}
                maxLength={34}
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">
                Organisation GitHub propriétaire (optionnel, sinon votre compte)
              </span>
              <input
                value={org}
                onChange={(e) => setOrg(e.target.value)}
                placeholder="Alpha-tech-CG"
                className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
              />
            </label>
            <button
              type="submit"
              className="cursor-pointer rounded-md bg-primary px-4 py-2 text-sm font-medium text-on-primary hover:opacity-90"
            >
              Créer l&apos;App sur GitHub
            </button>
          </form>
        </Card>
      ) : null}

      {manifest ? (
        <form ref={formRef} method="post" action={manifest.action} className="hidden">
          <input type="hidden" name="manifest" value={manifest.manifest} />
        </form>
      ) : null}
    </div>
  );
}
