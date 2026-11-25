import Link from "next/link";
import type { ReactNode } from "react";
import type { ApiError } from "@/lib/api";

/** Stored ids keep their original meaning. "RC" is configuration C in the study, and stored "C" is the heuristic-with-history control. */
export const CONFIG_ORDER = ["A", "B", "RC", "C", "D", "E"];

export const CONFIG_NAMES: Record<string, string> = {
  A: "A · Unprotected",
  B: "B · Rules only",
  RC: "C · Rules + heuristic",
  C: "Control · Heuristic + history",
  D: "D · Rules + ML",
  E: "E · Rules + ML + history",
};

export const CONFIG_HELP: Record<string, string> = {
  A: "No guard. Every proposed action runs inside the sandbox.",
  B: "Deterministic policy only.",
  RC: "Policy, then the rule-based contextual heuristic.",
  C: "Policy, heuristic and action history. Recommended: the best-measured configuration, with no false blocks in the benchmarks.",
  D: "Policy, then the ML assessor with no history.",
  E: "Policy, then the ML assessor with action history and untrusted tool output.",
};

export const CONFIG_COLORS: Record<string, string> = {
  A: "var(--color-cfg-a)",
  B: "var(--color-cfg-b)",
  RC: "var(--color-cfg-rc)",
  C: "var(--color-cfg-c)",
  D: "var(--color-cfg-d)",
  E: "var(--color-cfg-e)",
};

export const CATEGORY_NAMES: Record<string, string> = {
  benign: "Benign tasks",
  prompt_injection: "Prompt injection",
  permission_violation: "Permission violations",
  repeated_unnecessary: "Repeated or unnecessary",
  injecagent_direct_harm: "InjecAgent: direct harm",
  injecagent_data_stealing: "InjecAgent: data stealing",
};

export const SPLIT_NAMES: Record<string, string> = {
  all: "All", dev: "Dev (tuned)", holdout: "Internal holdout", external: "InjecAgent (external)",
};

export function pct(value: number | null | undefined, digits = 1): string {
  return value === null || value === undefined ? "n/a" : `${(value * 100).toFixed(digits)}%`;
}

export function shortTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "unknown time";
  return date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function latency(us: number | null | undefined): string {
  if (us === null || us === undefined) return "n/a";
  return us >= 1000 ? `${(us / 1000).toFixed(2)} ms` : `${us.toFixed(0)} µs`;
}

export function actionTarget(args: Record<string, unknown> | string | null | undefined): string {
  if (!args) return "";
  if (typeof args === "string") return args;
  const value = args.path ?? args.target ?? args.url ?? args.command ?? args.app_tool;
  return typeof value === "string" ? value : JSON.stringify(args);
}

/** Which layer made the final decision, in words. Stored values: policy (rules decided alone), context (the contextual
 * assessor tightened the rules' verdict), policy+context (both ran and agreed). */
export function decidedBy(source: string | null | undefined, ruleId?: string | null): string {
  if (ruleId) return ruleId;
  if (source === "policy") return "Rules";
  if (source === "context") return "Contextual check";
  if (source === "policy+context") return "Rules and contextual check agreed";
  return source ?? "-";
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <header className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-ink-2">{description}</p>}
      </div>
      {actions}
    </header>
  );
}

export function Panel({ title, subtitle, actions, children, className = "" }: {
  title?: string; subtitle?: string; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`min-w-0 rounded-md border border-line bg-panel ${className}`}>
      {(title || actions) && (
        <div className="flex flex-wrap items-start justify-between gap-2 border-b border-line px-4 py-3">
          <div>
            {title && <h2 className="text-[13px] font-semibold">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-ink-3">{subtitle}</p>}
          </div>
          {actions}
        </div>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

type Tone = "good" | "warn" | "serious" | "critical" | "neutral";

const TONE_COLOR: Record<Tone, string> = {
  good: "var(--color-good)",
  warn: "var(--color-warn)",
  serious: "var(--color-serious)",
  critical: "var(--color-critical)",
  neutral: "var(--color-ink-3)",
};

/** Status always carries a glyph and a label, so it never relies on color alone. */
export function Status({ tone, glyph, children }: { tone: Tone; glyph: string; children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded border border-line bg-raised px-1.5 py-0.5 text-xs">
      <span aria-hidden style={{ color: TONE_COLOR[tone] }} className="font-bold">{glyph}</span>
      {children}
    </span>
  );
}

/** Allow is the only positive state. Escalation is amber, any denial red, and anything unrecognised is shown as unknown, never as success. */
export function DecisionBadge({ decision, approval }: { decision: string | null; approval?: string | null }) {
  if (!decision) return <Status tone="neutral" glyph="…">Evaluating</Status>;
  if (decision === "ALLOW") return <Status tone="good" glyph="✓">Allowed</Status>;
  if (decision === "BLOCK") return <Status tone="critical" glyph="✕">Blocked</Status>;
  if (decision !== "APPROVAL_REQUIRED") return <Status tone="neutral" glyph="!">Unknown decision</Status>;
  if (approval === "approved") return <Status tone="good" glyph="✓">Approved by a person</Status>;
  if (approval === "denied") return <Status tone="critical" glyph="✕">Approval denied</Status>;
  if (approval === "timeout") return <Status tone="critical" glyph="✕">Approval timed out</Status>;
  return <Status tone="warn" glyph="?">Needs approval</Status>;
}

export function RiskBadge({ level }: { level: string | null | undefined }) {
  if (!level) return null;
  const tone: Tone = level === "low" ? "good" : level === "medium" ? "warn" : level === "high" ? "serious" : "critical";
  return <Status tone={tone} glyph="◆">Risk: {level}</Status>;
}

export function RunStatus({ status, reason }: { status: string; reason?: string | null }) {
  if (status === "running") return <span className="inline-flex items-center gap-1.5 text-xs"><span className="pulse-dot h-2 w-2 rounded-full bg-accent" />Running</span>;
  if (status === "queued") return <Status tone="neutral" glyph="…">Queued</Status>;
  if (status === "completed") return <Status tone="good" glyph="✓">Completed</Status>;
  if (status === "terminated") return <Status tone="warn" glyph="■">{(reason ?? "terminated").replaceAll("_", " ")}</Status>;
  if (status === "cancelled") return <Status tone="neutral" glyph="■">Cancelled</Status>;
  if (status === "skipped") return <Status tone="neutral" glyph="–">Skipped</Status>;
  if (reason === "interrupted") return <Status tone="serious" glyph="!">Interrupted by a restart</Status>;
  return <Status tone="critical" glyph="!">{status === "failed" ? "Failed" : "Error"}</Status>;
}

export function ConfigTag({ id }: { id: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs">
      <span aria-hidden className="h-2.5 w-2.5 rounded-sm" style={{ background: CONFIG_COLORS[id] }} />
      {CONFIG_NAMES[id] ?? id}
    </span>
  );
}

export function Provenance({ provider, assessor, note }: { provider: string; assessor?: string | null; note?: string }) {
  const scripted = provider === "scripted";
  assessor = assessor === "heuristic" ? null : assessor;
  return (
    <div className="mb-4 flex gap-3 rounded-md border border-line-strong bg-raised px-4 py-3">
      <span aria-hidden className="mt-0.5 font-bold" style={{ color: scripted ? "var(--color-warn)" : "var(--color-accent)" }}>{scripted ? "!" : "i"}</span>
      <div>
        <div className="text-[13px] font-semibold">
          Agent: {scripted ? "scripted traces" : provider}{assessor ? ` · Assessor: ${assessor}` : ""}
        </div>
        {note && <p className="mt-0.5 text-xs text-ink-2">{note}</p>}
      </div>
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-md border border-dashed border-line-strong px-6 py-10 text-center">
      <div className="font-medium">{title}</div>
      {children && <div className="mx-auto mt-1 max-w-md text-[13px] text-ink-2">{children}</div>}
    </div>
  );
}

export function ErrorNotice({ error }: { error: ApiError | Error | null }) {
  if (!error) return null;
  return (
    <div role="alert" className="mb-4 rounded-md border border-critical bg-raised px-4 py-3 text-[13px]">
      <span aria-hidden className="mr-2 font-bold text-critical">!</span>
      {error.message}
      {"status" in error && error.status === 0 && (
        <span className="text-ink-2"> Start it with <code className="font-mono text-xs">python -m boundaryguard.main</code> in the backend folder.</span>
      )}
    </div>
  );
}

/** Confirms an operation the backend has acknowledged. Never shown before the response arrives. */
export function SuccessNotice({ message, onDismiss }: { message: string | null; onDismiss?: () => void }) {
  if (!message) return null;
  return (
    <div role="status" className="mb-4 flex items-start gap-2 rounded-md border border-good bg-raised px-4 py-3 text-[13px]">
      <span aria-hidden className="font-bold text-good">✓</span>
      <span className="flex-1">{message}</span>
      {onDismiss && <button type="button" onClick={onDismiss} className="text-xs text-ink-3 hover:text-ink" aria-label="Dismiss">Dismiss</button>}
    </div>
  );
}

export function Loading() {
  return <div className="py-10 text-center text-[13px] text-ink-3">Loading…</div>;
}

const BUTTON = "inline-flex items-center justify-center gap-1.5 rounded px-3 py-1.5 text-[13px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50";

export function Button({ variant = "secondary", className = "", ...props }: React.ComponentProps<"button"> & { variant?: "primary" | "secondary" | "danger" }) {
  const look = variant === "primary"
    ? "bg-accent text-bg hover:bg-ink"
    : variant === "danger"
      ? "border border-critical hover:bg-raised"
      : "border border-line-strong hover:bg-raised";
  return <button type="button" className={`${BUTTON} ${look} ${className}`} {...props} />;
}

export function LinkButton({ href, children, download }: { href: string; children: ReactNode; download?: boolean }) {
  if (download) {
    return <a href={href} download className={`${BUTTON} border border-line-strong hover:bg-raised`}>{children}</a>;
  }
  return <Link href={href} className={`${BUTTON} border border-line-strong hover:bg-raised`}>{children}</Link>;
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs text-ink-2">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-ink-3">{hint}</span>}
    </label>
  );
}
