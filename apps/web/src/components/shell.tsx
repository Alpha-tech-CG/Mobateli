"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { ShieldCheck, LayoutDashboard, GitPullRequest, ScrollText, LogOut } from "lucide-react";
import { clearToken, getToken } from "@/lib/api";

const NAV = [
  { href: "/", label: "Vue d'ensemble", icon: LayoutDashboard },
  { href: "/pull-requests", label: "Pull requests", icon: GitPullRequest },
  { href: "/policies", label: "Politiques", icon: ScrollText },
];

/** App shell with sidebar nav + client-side auth guard. */
export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (!getToken()) router.replace("/login");
    else setReady(true);
  }, [router]);

  if (!ready) return null;

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-60 shrink-0 flex-col border-r border-border bg-card">
        <div className="flex items-center gap-2 px-5 py-4">
          <ShieldCheck className="size-6 text-primary" aria-hidden />
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
      <main className="flex-1 overflow-x-hidden px-6 py-6">{children}</main>
    </div>
  );
}
