import Link from "next/link";
import type { ReactNode } from "react";

/** Shared frame for /login and /signup, matching the marketing site's look. */
export function AuthShell({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string;
  subtitle: string;
  children: ReactNode;
  footer: ReactNode;
}) {
  return (
    <div className="relative flex min-h-screen flex-col overflow-hidden bg-[#111111] text-white">
      <div
        className="absolute inset-0 opacity-60"
        style={{
          backgroundImage:
            "linear-gradient(to right,#1c1d1e 1px,transparent 1px),linear-gradient(to bottom,#1c1d1e 1px,transparent 1px)",
          backgroundSize: "120px 120px",
        }}
        aria-hidden
      />
      <header className="relative mx-auto flex h-[76px] w-full max-w-[1280px] items-center px-6">
        <Link href="/" className="flex items-center gap-2.5">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/logo.webp" alt="CodeGate" className="size-8" />
          <span className="font-display text-[20px]">CodeGate</span>
        </Link>
      </header>
      <main className="relative flex flex-1 items-center justify-center px-4 pb-16">
        <div className="w-full max-w-[420px] rounded-[6px] border border-[#26292b] bg-[#17191a] p-8">
          <h1 className="font-display text-[32px] leading-tight">{title}</h1>
          <p className="mt-2 text-[14px] text-[#9aa3a8]">{subtitle}</p>
          <div className="mt-7">{children}</div>
          <div className="mt-6 border-t border-[#26292b] pt-5 text-center text-[14px] text-[#9aa3a8]">
            {footer}
          </div>
        </div>
      </main>
    </div>
  );
}

export function AuthField({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-[13px] text-[#c4c9cc]">{label}</span>
      {children}
      {hint ? <span className="mt-1 block text-[12px] text-[#7d868b]">{hint}</span> : null}
    </label>
  );
}

export const authInput =
  "h-11 w-full rounded-[6px] border border-[#2c2f31] bg-[#111111] px-3.5 text-[14px] text-white outline-none transition-colors placeholder:text-[#5f676c] focus:border-[#bb3e2c]";

export function AuthSubmit({ busy, children }: { busy: boolean; children: ReactNode }) {
  return (
    <button
      type="submit"
      disabled={busy}
      className="h-12 w-full cursor-pointer rounded-[40px] bg-[#bb3e2c] text-[14px] font-medium text-white transition-colors duration-200 hover:bg-[#a63523] disabled:cursor-wait disabled:opacity-60"
    >
      {children}
    </button>
  );
}
