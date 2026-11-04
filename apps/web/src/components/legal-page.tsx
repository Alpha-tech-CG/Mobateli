import Link from "next/link";
import type { ReactNode } from "react";
import { COMPANY, LEGAL_VERSION, missing } from "@/lib/legal";

/** Shared frame for the public legal pages. */
export function LegalPage({ title, intro, children }: { title: string; intro?: ReactNode; children: ReactNode }) {
  return (
    <div className="min-h-screen bg-[#111111] text-white">
      <header className="mx-auto flex h-[76px] max-w-[880px] items-center justify-between px-6">
        <Link href="/" className="flex items-center gap-2.5">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/logo.webp" alt="CodeGate" className="size-8" />
          <span className="font-display text-[20px]">CodeGate</span>
        </Link>
        <nav className="flex flex-wrap gap-x-4 gap-y-1 text-[13px] text-white/60" aria-label="Documents légaux">
          <Link href="/legal" className="hover:text-white">Mentions légales</Link>
          <Link href="/terms" className="hover:text-white">CGU / CGV</Link>
          <Link href="/privacy" className="hover:text-white">Confidentialité</Link>
          <Link href="/dpa" className="hover:text-white">Sous-traitance (DPA)</Link>
        </nav>
      </header>
      <main className="mx-auto max-w-[880px] px-6 pb-24 pt-8">
        <h1 className="font-display text-[40px] leading-tight">{title}</h1>
        <p className="mt-2 text-[13px] text-white/50">Version du {new Date(LEGAL_VERSION).toLocaleDateString("fr-FR", { dateStyle: "long" })}</p>
        {intro ? <div className="mt-6 text-[15px] leading-relaxed text-white/80">{intro}</div> : null}
        <div className="legal mt-10 space-y-10 text-[15px] leading-relaxed text-white/80">{children}</div>
      </main>
    </div>
  );
}

export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-3">
      <h2 className="text-[20px] font-semibold text-white">{title}</h2>
      {children}
    </section>
  );
}

/** A company field, visibly flagged while it has not been filled in. */
export function Field({ value, label }: { value: string; label: string }) {
  return missing(value) ? (
    <span className="rounded bg-[#bb3e2c]/20 px-1.5 py-0.5 text-[#e8836f]">[{label} — à compléter]</span>
  ) : (
    <>{value}</>
  );
}

export function contact() {
  return <Field value={COMPANY.contactEmail} label="email de contact" />;
}
