"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import {
  actionTarget, Button, ConfigTag, decidedBy, DecisionBadge, EmptyState, ErrorNotice, Field, LinkButton, PageHeader, Panel, RiskBadge, shortTime, Status,
} from "@/components/ui";
import { api, API, ApiError, usePoll, type AuditItem, type RepeatedViolation } from "@/lib/api";

const PAGE_SIZE = 25;

function query(filters: Record<string, string>, extra: Record<string, string | number> = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) if (value) params.set(key, value);
  for (const [key, value] of Object.entries(extra)) params.set(key, String(value));
  return params.toString();
}

function VerifyChain({ runId }: { runId: string }) {
  const [result, setResult] = useState<{ valid: boolean; events: number; problem: string | null } | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  if (result) {
    return result.valid
      ? <Status tone="good" glyph="✓">Chain valid ({result.events} events)</Status>
      : <Status tone="critical" glyph="!">Tampering detected: {result.problem}</Status>;
  }
  return (
    <>
      <ErrorNotice error={error} />
      <Button onClick={() => { api<typeof result>(`/audit/verify/${runId}`).then(setResult).catch(setError); }}>Verify hash chain</Button>
    </>
  );
}

export default function AuditPage() {
  return <Suspense fallback={null}><AuditContent /></Suspense>;
}

function AuditContent() {
  const params = useSearchParams();
  const router = useRouter();
  const [form, setForm] = useState({ q: params.get("q") ?? "", decision: params.get("decision") ?? "", tool: params.get("tool") ?? "", rule_id: params.get("rule_id") ?? "", gt_label: params.get("gt_label") ?? "" });
  const EMPTY = { q: "", decision: "", tool: "", rule_id: "", gt_label: "" };

  /** Apply filters and mirror them in the address bar, so a filtered view can be shared or bookmarked. */
  function apply(next: typeof form) {
    const trimmed = { ...next, q: next.q.trim(), rule_id: next.rule_id.trim() };
    setForm(trimmed);
    setOffset(0);
    setFilters(trimmed);
    setExpanded(null);
    const search = query(trimmed);
    router.replace(search ? `/audit?${search}` : "/audit", { scroll: false });
  }
  const [filters, setFilters] = useState(form);
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const log = usePoll<{ total: number; items: AuditItem[] }>(`/audit?${query(filters, { limit: PAGE_SIZE, offset })}`);
  const repeated = usePoll<RepeatedViolation[]>("/audit/repeated?limit=10");

  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setForm({ ...form, [key]: e.target.value });
  const total = log.data?.total ?? 0;

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every proposed action and the decision made about it. Records are append-only and hash-chained per run, so they cannot be edited or deleted."
        actions={
          <div className="flex gap-2">
            <LinkButton download href={`${API}/audit/export?${query(filters, { format: "csv" })}`}>Export CSV</LinkButton>
            <LinkButton download href={`${API}/audit/export?${query(filters, { format: "json" })}`}>Export JSON</LinkButton>
          </div>
        }
      />
      <ErrorNotice error={log.error} />

      <Panel className="mb-4">
        <form className="grid grid-cols-1 gap-3 md:grid-cols-[1fr_repeat(4,9rem)_auto] md:items-end"
          onSubmit={(e) => { e.preventDefault(); apply(form); }}>
          <Field label="Search"><input type="search" placeholder="Path, reason, scenario, rule…" value={form.q} onChange={set("q")} /></Field>
          <Field label="Decision">
            <select value={form.decision} onChange={set("decision")}>
              <option value="">Any</option><option value="ALLOW">Allow</option><option value="BLOCK">Block</option><option value="APPROVAL_REQUIRED">Approval</option>
            </select>
          </Field>
          <Field label="Tool">
            <select value={form.tool} onChange={set("tool")}>
              <option value="">Any</option>
              {["list_dir", "read_file", "write_file", "delete_file", "run_tests", "http_request", "shell_exec", "app_call"].map((t) => <option key={t}>{t}</option>)}
            </select>
          </Field>
          <Field label="Rule"><input placeholder="PATH_PROTECTED" value={form.rule_id} onChange={set("rule_id")} /></Field>
          <Field label="Ground truth">
            <select value={form.gt_label} onChange={set("gt_label")}>
              <option value="">Any</option><option value="unauthorized">Unauthorized</option><option value="legitimate">Legitimate</option><option value="unlabeled">Unlabeled</option>
            </select>
          </Field>
          <div className="flex gap-2">
            <Button type="submit" variant="primary" className="h-[33px]">Apply</Button>
            <Button className="h-[33px]" disabled={Object.values(form).every((v) => !v) && Object.values(filters).every((v) => !v)} onClick={() => apply(EMPTY)}>Reset</Button>
          </div>
        </form>
      </Panel>

      <Panel className="mb-4" title={`Decisions (${total.toLocaleString()})`}>
        {log.data && log.data.items.length === 0 ? (
          <EmptyState title="No matching records">{Object.values(filters).every((v) => !v) ? "Nothing has been decided yet. Start a live run or an experiment." : "Try loosening the filters, or reset them."}</EmptyState>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table>
                <thead><tr><th>Time</th><th>Decision</th><th>Action</th><th>Decided by</th><th>Configuration</th><th>Scenario</th></tr></thead>
                <tbody>
                  {(log.data?.items ?? []).map((item) => (
                    <FragmentRow key={item.action_id} item={item} open={expanded === item.action_id} onToggle={() => setExpanded(expanded === item.action_id ? null : item.action_id)} />
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-3 flex items-center justify-between text-xs text-ink-2">
              <span className="tnum">{total ? `${offset + 1} to ${Math.min(offset + PAGE_SIZE, total)} of ${total.toLocaleString()}` : ""}</span>
              <div className="flex gap-2">
                <Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous</Button>
                <Button disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>Next</Button>
              </div>
            </div>
          </>
        )}
      </Panel>

      <Panel title="Repeated violations" subtitle="The same canonical action denied more than once in a run. Different spellings of one path count as the same action.">
        {repeated.data && repeated.data.length === 0 ? <EmptyState title="No repeated violations recorded" /> : (
          <div className="overflow-x-auto">
            <table>
              <thead><tr><th>Action</th><th className="text-right">Denials</th><th>Configuration</th><th>Scenario</th><th>Run ended by</th></tr></thead>
              <tbody>
                {(repeated.data ?? []).map((r) => (
                  <tr key={`${r.run_id}-${r.fingerprint}`}>
                    <td className="max-w-80"><Link href={`/trace/${r.run_id}`} className="block truncate font-mono text-xs underline-offset-2 hover:underline">{r.tool} {actionTarget(r.args)}</Link></td>
                    <td className="tnum text-right">{r.denials}</td>
                    <td><ConfigTag id={r.configuration} /></td>
                    <td className="font-mono text-xs text-ink-2">{r.scenario_id ?? "-"}</td>
                    <td className="text-xs text-ink-2">{(r.termination_reason ?? "-").replaceAll("_", " ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}

function FragmentRow({ item, open, onToggle }: { item: AuditItem; open: boolean; onToggle: () => void }) {
  return (
    <>
      <tr className="cursor-pointer hover:bg-raised" onClick={onToggle}>
        <td className="tnum whitespace-nowrap text-xs text-ink-2">{shortTime(item.decided_at)}</td>
        <td><DecisionBadge decision={item.final_decision} approval={item.approval_outcome} /></td>
        <td className="max-w-72">
          <button type="button" aria-expanded={open} className="max-w-full text-left" onClick={(e) => { e.stopPropagation(); onToggle(); }}>
            <span className="block font-mono text-xs">{item.tool}</span>
            <span className="block truncate font-mono text-xs text-ink-3">{actionTarget(item.args)}</span>
          </button>
        </td>
        <td className={`text-xs text-ink-2 ${item.rule_id ? "font-mono" : ""}`}>{decidedBy(item.source, item.rule_id)}</td>
        <td><ConfigTag id={item.configuration} /></td>
        <td className="font-mono text-xs text-ink-2">{item.scenario_id ?? "custom"}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6} className="bg-bg">
            <div className="space-y-2 py-1 text-[13px]">
              <p className="text-ink-2">{item.reasoning}</p>
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <RiskBadge level={item.risk_level} />
                <span className="text-ink-3">Executed: {item.exec_status ?? "no"}</span>
                {item.gt_label && <span className="text-ink-3">Ground truth: {item.gt_label}</span>}
                <Link href={`/trace/${item.run_id}`} className="underline">Open trace</Link>
                <VerifyChain runId={item.run_id} />
              </div>
              <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-panel p-2 font-mono text-[11px]">{JSON.stringify(item.args, null, 2)}</pre>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
