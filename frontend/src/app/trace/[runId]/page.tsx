"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import {
  actionTarget, Button, ConfigTag, decidedBy, DecisionBadge, EmptyState, ErrorNotice, latency, Loading, PageHeader, Panel, Provenance,
  RiskBadge, RunStatus, Status,
} from "@/components/ui";
import { api, ApiError, usePoll, type Run, type TraceAction } from "@/lib/api";

function ExecutionOutcome({ action }: { action: TraceAction }) {
  if (!action.final_decision) return null;
  if (action.approval_status === "pending") return <span className="text-xs text-ink-2">Paused until you decide</span>;
  const permitted = action.final_decision === "ALLOW" || action.approval_outcome === "approved";
  if (!permitted) return <span className="text-xs text-ink-2">Not executed</span>;
  if (!action.exec_status) return <span className="text-xs text-ink-3">Executing…</span>;
  if (action.exec_status === "ok") return <Status tone="neutral" glyph="▸">Executed</Status>;
  if (action.exec_status === "refused") return <Status tone="serious" glyph="■">Refused by sandbox floor</Status>;
  return <Status tone="neutral" glyph="▸">Tool error</Status>;
}

function ActionCard({ action, onResolved }: { action: TraceAction; onResolved: () => void }) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const pending = action.approval_status === "pending";

  async function resolve(approve: boolean) {
    setBusy(true);
    setError(null);
    try {
      await api(`/approvals/${action.approval_id}/resolve`, { method: "POST", body: { approve } });
      onResolved();
    } catch (err) {
      setError(err as ApiError);
    } finally {
      setBusy(false);
    }
  }

  const target = action.exec_target ?? action.canonical?.real_virtual_path ?? null;
  const raw = actionTarget(action.args);

  return (
    <li className="relative pl-9">
      <span aria-hidden className="tnum absolute left-0 top-3 flex h-6 w-6 items-center justify-center rounded-full border border-line-strong bg-raised text-[11px]">{action.seq}</span>
      <div className={`rounded-md border bg-panel ${pending ? "border-warn" : "border-line"}`}>
        <div className="flex flex-wrap items-center gap-2 px-3 py-2.5">
          <span className="font-mono text-[13px] font-semibold">{action.tool}</span>
          <span className="min-w-0 flex-1 truncate font-mono text-xs text-ink-2" title={raw}>{raw}</span>
          <DecisionBadge decision={action.final_decision} approval={action.approval_outcome} />
          <RiskBadge level={action.risk_level} />
          <ExecutionOutcome action={action} />
        </div>
        {action.reasoning && (
          <div className="border-t border-line px-3 py-2 text-[13px] text-ink-2">
            {action.rule_id && <code className="mr-2 rounded bg-raised px-1 py-0.5 font-mono text-[11px] text-ink">{action.rule_id}</code>}
            {action.reasoning}
            {action.assessor_fallback && <span className="ml-1 text-ink-3">(assessor unavailable: fail-safe)</span>}
          </div>
        )}
        {pending && (
          <div className="flex items-center gap-2 border-t border-line px-3 py-2">
            <span className="mr-auto text-[13px]">This action is waiting for your decision.</span>
            <ErrorNotice error={error} />
            <Button disabled={busy} onClick={() => void resolve(false)}>Deny</Button>
            <Button variant="primary" disabled={busy} onClick={() => void resolve(true)}>Approve</Button>
          </div>
        )}
        <div className="border-t border-line px-3 py-1.5">
          <button type="button" aria-expanded={open} onClick={() => setOpen(!open)} className="text-xs text-ink-3 hover:text-ink">
            {open ? "Hide details" : "Show details"}
          </button>
          {open && (
            <dl className="mt-2 grid gap-x-4 gap-y-2 pb-1.5 text-xs md:grid-cols-[9rem_1fr]">
              <dt className="text-ink-3">Arguments</dt>
              <dd><pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-bg p-2 font-mono text-[11px]">{JSON.stringify(action.args, null, 2)}</pre></dd>
              {target && <><dt className="text-ink-3">Resolved target</dt><dd className="break-all font-mono">{target}</dd></>}
              <dt className="text-ink-3">Decided by</dt><dd>{decidedBy(action.source)}{action.assessor ? ` · assessor: ${action.assessor}` : ""}</dd>
              <dt className="text-ink-3">Latency</dt><dd className="tnum">Rules {latency(action.policy_latency_us)} · Context {latency(action.context_latency_us)}</dd>
              {action.risk_score !== null && <><dt className="text-ink-3">Risk score</dt><dd className="tnum">{action.risk_score.toFixed(2)}</dd></>}
              {(action.signals?.length ?? 0) > 0 && <>
                <dt className="text-ink-3">Signals</dt>
                <dd><ul className="space-y-1">{action.signals!.map((s) => (
                  <li key={s.name}><code className="font-mono">{s.name}</code> <span className="tnum text-ink-3">+{s.weight}{s.hard ? " · hard" : ""}</span><br /><span className="text-ink-2">{s.detail}</span></li>
                ))}</ul></dd>
              </>}
              {action.result_summary && <>
                <dt className="text-ink-3">Tool result</dt>
                <dd><pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-bg p-2 font-mono text-[11px]">{action.result_summary}</pre></dd>
              </>}
              {action.contains_canary && <><dt className="text-ink-3">Canary</dt><dd><Status tone="critical" glyph="!">Dummy credential {action.sink ? "left through the simulated network" : "exposed to the agent"}</Status></dd></>}
              {action.gt_label && action.gt_label !== "unlabeled" && <><dt className="text-ink-3">Ground truth</dt><dd>{action.gt_label} (scenario label, not seen by the guard)</dd></>}
              {action.approval_outcome === "approved" && action.gt_label === "unauthorized" && <><dt className="text-ink-3">Override</dt><dd><Status tone="warn" glyph="!">A person approved an action the scenario labels unauthorized</Status></dd></>}
            </dl>
          )}
        </div>
      </div>
    </li>
  );
}

function bool(value: boolean | null | undefined, yes: string, no: string) {
  if (value === null || value === undefined) return "-";
  return value ? yes : no;
}

export default function TraceDetailPage() {
  const { runId } = useParams<{ runId: string }>();
  const [finished, setFinished] = useState(false);
  const { data, error, loading, refresh } = usePoll<{ run: Run; actions: TraceAction[] }>(`/runs/${runId}/trace`, finished ? 0 : 1000);

  const running = data?.run.status === "running";
  // Stop polling once the run has ended. Adjusting state during render is the pattern React documents for this.
  if (data && !running && !finished) setFinished(true);

  if (loading && !data) return <Loading />;
  if (!data) {
    return (
      <>
        <PageHeader title="Run not available" />
        <ErrorNotice error={error} />
        <Link href="/trace" className="text-[13px] underline">Back to live runs</Link>
      </>
    );
  }
  const { run, actions } = data;

  return (
    <>
      <PageHeader
        title={run.scenario_id ?? "Custom task"}
        description={run.objective}
        actions={<Link href={run.experiment_id ? `/experiments/${run.experiment_id}` : "/trace"} className="text-xs underline">{run.experiment_id ? "Back to experiment" : "All live runs"}</Link>}
      />
      <ErrorNotice error={error} />
      <Provenance provider={run.agent_provider} assessor={run.assessor}
        note={run.agent_provider === "scripted" ? "A scripted agent attempts attacks because its trace says to. This shows how the guard responds, not how likely a real model is to try." : run.agent_model ? `Model: ${run.agent_model}` : undefined} />

      <div className="mb-4 flex flex-wrap items-center gap-x-6 gap-y-2 rounded-md border border-line bg-panel px-4 py-3 text-[13px]">
        <ConfigTag id={run.configuration} />
        <RunStatus status={run.status} reason={run.termination_reason} />
        <span className="tnum text-ink-2">{(run.step_count || actions.length) === 1 ? "1 step" : `${run.step_count || actions.length} steps`}</span>
        {!running && <span className="text-ink-2">Task: {bool(run.task_completed, "completed", "not completed")}</span>}
        {!running && run.security_pass !== null && <span className="text-ink-2">Security expectation: {bool(run.security_pass, "met", "not met")}</span>}
        {run.canary_exfiltrated && <Status tone="critical" glyph="!">Dummy credential exfiltrated (simulated)</Status>}
      </div>
      {run.error && <ErrorNotice error={new Error(run.error)} />}

      <Panel title="Action timeline">
        {actions.length === 0 ? (
          <EmptyState title={running ? "Waiting for the first action…" : "This run proposed no actions"} />
        ) : (
          <ol className="relative space-y-2 before:absolute before:bottom-3 before:left-[11px] before:top-3 before:w-px before:bg-line">
            {actions.map((a) => <ActionCard key={a.action_id} action={a} onResolved={refresh} />)}
          </ol>
        )}
        {run.final_message && !running && <p className="mt-3 border-t border-line pt-3 text-[13px] text-ink-2">Final message: {run.final_message}</p>}
      </Panel>
    </>
  );
}
