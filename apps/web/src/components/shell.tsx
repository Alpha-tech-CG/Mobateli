"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import {
  LayoutDashboard,
  GitPullRequest,
  ScrollText,
  Plug,
  FileClock,
  Bot,
  Rocket,
  Server,
  KeyRound,
  DatabaseBackup,
  ShieldCheck,
  ClipboardCheck,
  ScanSearch,
  Users,
  LogOut,
  UserRound,
  FolderGit2,
  SlidersHorizontal,
} from "lucide-react";
import { api, clearToken, getSession, getToken } from "@/lib/api";

const NAV = [
  { href: "/dashboard", label: "Vue d'ensemble", icon: LayoutDashboard },
  { href: "/pull-requests", label: "Pull requests", icon: GitPullRequest },
  { href: "/scans", label: "Analyser un dépôt", icon: ScanSearch },
  { href: "/repositories", label: "Dépôts", icon: FolderGit2 },
  { href: "/policies", label: "Politiques", icon: ScrollText },
  { href: "/settings/analysis", label: "Paramètres d'analyse", icon: SlidersHorizontal },
  { href: "/agent-guard", label: "Agent Guard", icon: Bot },
  { href: "/approvals", label: "Approbations", icon: ClipboardCheck },
  { href: "/deployments", label: "Déploiements", icon: Rocket },
  { href: "/servers", label: "Serveurs", icon: Server },
  { href: "/bruteforce", label: "Brute force", icon: KeyRound },
  { href: "/backups", label: "Sauvegardes", icon: DatabaseBackup },
  { href: "/integrations", label: "Intégrations", icon: Plug },
  { href: "/audit", label: "Audit", icon: FileClock },
  { href: "/members", label: "Membres", icon: Users },
  { href: "/settings/security", label: "Sécurité du compte", icon: ShieldCheck },
  { href: "/account", label: "Mon compte", icon: UserRound },
];

/** App shell with sidebar nav + client-side auth guard. */
export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [ready, setReady] = useState(false);

  const [needsMfa, setNeedsMfa] = useState(false);
  const [unverified, setUnverified] = useState<string | null>(null);
  const [resend, setResend] = useState<"idle" | "sending" | "sent" | "error">("idle");

  useEffect(() => {
    const session = getSession();
    // Expired sessions (cahier §10.2) go back to login.
    if (!getToken() || !session || (session.exp && session.exp * 1000 < Date.now())) {
      clearToken();
      router.replace("/login");
      return;
    }
    setNeedsMfa((session.role === "owner" || session.role === "admin") && !session.mfa);
    setReady(true);
    api<{ user: { email: string; emailVerified: boolean } }>("/api/v1/me")
      .then((r) => setUnverified(r.user.emailVerified ? null : r.user.email))
      .catch(() => undefined);
  }, [router]);

  async function resendVerification() {
    setResend("sending");
    try {
      const r = await api<{ sent: boolean; alreadyVerified: boolean }>("/api/v1/auth/verify-email/resend", { method: "POST" });
      if (r.alreadyVerified) setUnverified(null);
      setResend(r.sent || r.alreadyVerified ? "sent" : "error");
    } catch {
      setResend("error");
    }
  }

  if (!ready) return null;

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-60 shrink-0 flex-col border-r border-border bg-card">
        <div className="flex items-center gap-2 px-5 py-4">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/logo.webp" alt="CodeGate" className="size-7" />
          <span className="font-mono text-lg font-semibold">CodeGate</span>
        </div>
        <nav className="flex-1 px-2 py-2" aria-label="Navigation principale">
          {NAV.map(({ href, label, icon: Icon }) => {
            const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                className={`mb-1 flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors duration-150 ${
                  active
                    ? "bg-primary text-on-primary"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground"
                }`}
              >
                <Icon className="size-4" aria-hidden />
                {label}
              </Link>
            );
          })}
        </nav>
        <button
          onClick={() => {
            clearToken();
            router.replace("/login");
          }}
          className="m-2 flex cursor-pointer items-center gap-3 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors duration-150 hover:bg-muted hover:text-foreground"
        >
          <LogOut className="size-4" aria-hidden />
          Se déconnecter
        </button>
      </aside>
      <main className="min-w-0 flex-1 overflow-x-hidden px-6 py-6">
        {unverified ? (
          <div
            className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-muted/60 px-4 py-3 text-sm"
            role="status"
          >
            <span>
              Confirmez votre adresse <span className="font-medium">{unverified}</span> avec le lien reçu par email
              pour recevoir les alertes de sécurité.
              {resend === "sent" ? " Nouveau lien envoyé." : resend === "error" ? " Envoi impossible, réessayez plus tard." : ""}
            </span>
            <button
              type="button"
              onClick={resendVerification}
              disabled={resend === "sending" || resend === "sent"}
              className="cursor-pointer rounded-md border border-border px-3 py-1.5 text-sm font-medium hover:bg-muted disabled:cursor-default disabled:opacity-60"
            >
              {resend === "sending" ? "Envoi…" : "Renvoyer le lien"}
            </button>
          </div>
        ) : null}
        {needsMfa && pathname !== "/settings/security" ? (
          <div className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm">
            <span>
              La double authentification (MFA) est obligatoire pour les administrateurs : les
              actions d&apos;administration restent bloquées jusqu&apos;à son activation.
            </span>
            <Link
              href="/settings/security"
              className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-on-primary hover:opacity-90"
            >
              Activer la MFA
            </Link>
          </div>
        ) : null}
        {children}
      </main>
    </div>
  );
}
