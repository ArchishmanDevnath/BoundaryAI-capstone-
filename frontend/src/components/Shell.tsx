"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { usePoll, type Approval, type Health } from "@/lib/api";

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/trace", label: "Live runs" },
  { href: "/experiments", label: "Experiments" },
  { href: "/model", label: "Risk model" },
  { href: "/policies", label: "Policies" },
  { href: "/audit", label: "Audit log" },
];

function StatusLine({ ok, label, offText = "Offline" }: { ok: boolean | null; label: string; offText?: string }) {
  return (
    <div className="flex items-center justify-between gap-2 text-xs">
      <span className="text-ink-3">{label}</span>
      <span>
        <span aria-hidden className="mr-1 font-bold" style={{ color: ok === null ? "var(--color-ink-3)" : ok ? "var(--color-good)" : "var(--color-serious)" }}>
          {ok === null ? "…" : ok ? "●" : "○"}
        </span>
        {ok === null ? "Checking" : ok ? "Online" : offText}
      </span>
    </div>
  );
}

export default function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const { data: health, error } = usePoll<Health>("/health", 5000);
  // Pending approvals are the one thing that needs a person, so they are visible from every page.
  const approvals = usePoll<Approval[]>("/approvals", 3000);
  const reachable = error ? false : health ? true : null;
  const waiting = approvals.data?.length ?? 0;

  return (
    <div className="min-h-screen md:grid md:grid-cols-[13.5rem_1fr]">
      <aside className="border-b border-line bg-panel md:sticky md:top-0 md:flex md:h-screen md:flex-col md:border-b-0 md:border-r">
        <div className="px-4 py-4">
          <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight">
            <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden fill="none">
              <path d="M10 1.5 17.5 4v5.5c0 4.3-3 7.4-7.5 9-4.5-1.6-7.5-4.7-7.5-9V4L10 1.5Z" stroke="var(--color-accent)" strokeWidth="1.5" />
              <path d="m6.5 10 2.5 2.5 4.5-5" stroke="var(--color-ink)" strokeWidth="1.5" />
            </svg>
            BoundaryGuard
          </Link>
          <div className="mt-0.5 pl-7 text-xs text-ink-3">Runtime authorization for AI agents</div>
        </div>
        <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-2 pb-2 md:flex-1 md:flex-col md:overflow-visible">
          {NAV.map((item) => {
            const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
            const badge = item.href === "/trace" && waiting > 0;
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={`flex items-center justify-between gap-2 whitespace-nowrap rounded px-2.5 py-1.5 text-[13px] ${active ? "bg-raised font-medium text-ink" : "text-ink-2 hover:bg-raised"}`}
              >
                {item.label}
                {badge && (
                  <span className="tnum rounded-full px-1.5 text-[11px] font-semibold text-bg" style={{ background: "var(--color-warn)" }}
                    title={`${waiting} action${waiting === 1 ? "" : "s"} waiting for your approval`}>
                    {waiting}<span className="sr-only"> waiting for approval</span>
                  </span>
                )}
              </Link>
            );
          })}
        </nav>
        <div className="hidden border-t border-line px-4 py-3 md:block">
          <StatusLine ok={reachable} label="Backend" />
          {reachable === false && <p className="mt-1 text-[11px] text-ink-3">Start it with python -m boundaryguard.main in the backend folder.</p>}
        </div>
      </aside>
      <main className="min-w-0 px-4 py-5 md:px-7 md:py-6">{children}</main>
    </div>
  );
}
