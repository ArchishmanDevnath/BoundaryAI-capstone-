"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useMemo, useState } from "react";
import { ConfirmDialog } from "@/components/Confirm";
import Results from "@/components/Results";
import {
  Button, CATEGORY_NAMES, CONFIG_NAMES, CONFIG_ORDER, EmptyState, ErrorNotice, LinkButton, Loading, PageHeader, Panel, Provenance, RunStatus,
} from "@/components/ui";
import { api, API, ApiError, usePoll, type Experiment, type ExperimentResult } from "@/lib/api";

const ACTIVE = ["queued", "running"];
const PAGE = 600;

function Cell({ result }: { result: ExperimentResult | undefined }) {
  if (!result) return <td className="text-center text-ink-3">-</td>;
  const problem = result.status === "error" || result.status === "skipped";
  const executed = result.unauthorized_executed > 0;
  const falseBlock = result.legitimate_blocked > 0;
  const glyph = problem ? "!" : executed ? "✕" : falseBlock ? "▲" : "✓";
  const color = problem ? "var(--color-serious)" : executed ? "var(--color-critical)" : falseBlock ? "var(--color-warn)" : "var(--color-good)";
  const text = problem
    ? result.status
    : executed
      ? `${result.unauthorized_executed}/${result.unauthorized_attempted} ran`
      : falseBlock
        ? `${result.legitimate_blocked} false`
        : result.unauthorized_attempted > 0
          ? `0/${result.unauthorized_attempted} ran`
          : "clean";
  return (
    <td className="whitespace-nowrap">
      <Link href={`/trace/${result.run_id}`} className="tnum inline-flex items-center gap-1.5 text-xs underline-offset-2 hover:underline"
        title={`${CONFIG_NAMES[result.configuration]}: task ${result.task_completed ? "completed" : "not completed"}, ${result.actions_total} actions`}>
        <span aria-hidden className="font-bold" style={{ color }}>{glyph}</span>{text}
      </Link>
    </td>
  );
}

function ScenarioMatrix({ id, active, total }: { id: string; active: boolean; total: number }) {
  const [category, setCategory] = useState("");
  const [page, setPage] = useState(0);
  const query = `/experiments/${id}/runs?limit=${PAGE}&offset=${page * PAGE}${category ? `&category=${category}` : ""}`;
  const results = usePoll<ExperimentResult[]>(query, active ? 2000 : 0);
  const data = results.data;
  const configs = useMemo(() => CONFIG_ORDER.filter((c) => data?.some((r) => r.configuration === c)), [data]);
  const rows = useMemo(() => {
    const scenarios = new Map<string, { id: string; title: string | null; category: string; split: string; cells: Record<string, ExperimentResult> }>();
    for (const r of data ?? []) {
      const row = scenarios.get(r.scenario_id) ?? { id: r.scenario_id, title: r.title, category: r.category, split: r.split, cells: {} };
      // With repeats, show the worst repeat rather than hiding a failure.
      const existing = row.cells[r.configuration];
      if (!existing || r.unauthorized_executed > existing.unauthorized_executed || r.legitimate_blocked > existing.legitimate_blocked) row.cells[r.configuration] = r;
      scenarios.set(r.scenario_id, row);
    }
    return [...scenarios.values()];
  }, [data]);
  const paged = total > PAGE;

  return (
    <Panel
      title="Scenario results"
      subtitle="✓ no unauthorized action ran and nothing legitimate was blocked · ✕ an unauthorized action ran · ▲ a legitimate action was blocked. Select a cell to open its trace."
      actions={
        <select aria-label="Filter by category" value={category} onChange={(ev) => { setPage(0); setCategory(ev.target.value); }} className="w-auto">
          <option value="">All categories</option>
          {Object.entries(CATEGORY_NAMES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
      }
    >
      <ErrorNotice error={results.error} />
      {rows.length === 0 ? (
        <EmptyState title={results.loading ? "Loading…" : "No results"}>{active ? "The first runs will appear here shortly." : "No runs match this filter."}</EmptyState>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table>
              <thead><tr><th>Scenario</th><th>Category</th>{configs.map((c) => <th key={c}>{CONFIG_NAMES[c]}</th>)}</tr></thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id}>
                    <td className="max-w-72"><span className="block truncate" title={row.title ?? row.id}>{row.title ?? row.id}</span><span className="block truncate font-mono text-[11px] text-ink-3">{row.id} · {row.split}</span></td>
                    <td className="whitespace-nowrap text-xs text-ink-2">{CATEGORY_NAMES[row.category] ?? row.category}</td>
                    {configs.map((c) => <Cell key={c} result={row.cells[c]} />)}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {paged && (
            <div className="mt-3 flex items-center justify-between text-xs text-ink-2">
              <span>Page {page + 1}. Rows are runs grouped by scenario. Export CSV for everything.</span>
              <div className="flex gap-2">
                <Button disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</Button>
                <Button disabled={(data?.length ?? 0) < PAGE} onClick={() => setPage(page + 1)}>Next</Button>
              </div>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

export default function ExperimentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const experiment = usePoll<Experiment>(`/experiments/${id}`, 1500);
  const active = experiment.data ? ACTIVE.includes(experiment.data.status) : true;
  const [tab, setTab] = useState<"results" | "scenarios">("results");
  const [error, setError] = useState<ApiError | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [cancelling, setCancelling] = useState(false);

  if (experiment.loading && !experiment.data) return <Loading />;
  if (!experiment.data) {
    return (
      <>
        <PageHeader title="Experiment not available" />
        <ErrorNotice error={experiment.error} />
        <Link href="/experiments" className="text-[13px] underline">Back to experiments</Link>
      </>
    );
  }
  const e = experiment.data;
  const progress = e.total_runs ? e.completed_runs / e.total_runs : 0;
  const model = e.manifest.model;

  async function cancel() {
    setCancelling(true);
    try {
      await api(`/experiments/${id}/cancel`, { method: "POST" });
      experiment.refresh();
    } catch (err) {
      setError(err as ApiError);
    } finally {
      setCancelling(false);
      setConfirming(false);
    }
  }

  return (
    <>
      <PageHeader
        title={e.name}
        description={`${e.manifest.suite === "injecagent" ? "InjecAgent external benchmark" : "Internal benchmark"} · ${e.total_runs.toLocaleString()} runs`}
        actions={
          <div className="flex flex-wrap gap-2">
            {active && <Button variant="danger" onClick={() => setConfirming(true)}>Cancel experiment</Button>}
            <LinkButton download href={`${API}/experiments/${id}/export?format=csv`}>Export CSV</LinkButton>
            <LinkButton download href={`${API}/experiments/${id}/export?format=json`}>Export JSON</LinkButton>
          </div>
        }
      />
      <ErrorNotice error={error} />
      <Provenance provider={e.manifest.agent_provider} note={e.manifest.provenance} />

      <Panel className="mb-4">
        <div className="flex flex-wrap items-center gap-4">
          <RunStatus status={e.status} />
          <div className="min-w-48 flex-1">
            <div className="h-1.5 rounded bg-raised"><div className="h-full rounded bg-accent transition-all" style={{ width: `${progress * 100}%` }} /></div>
          </div>
          <span className="tnum text-xs text-ink-2">{e.completed_runs.toLocaleString()} of {e.total_runs.toLocaleString()} runs</span>
        </div>
        {e.error && <p className="mt-2 text-[13px] text-ink-2">{e.error}</p>}
        <details className="mt-3 text-xs">
          <summary className="cursor-pointer text-ink-3">Reproducibility manifest</summary>
          <dl className="mt-2 grid gap-x-4 gap-y-1 font-mono md:grid-cols-[10rem_1fr]">
            <dt className="text-ink-3">Scenario suite</dt><dd className="break-all">{e.manifest.suite ?? "internal"} · {e.manifest.suite_hash}</dd>
            <dt className="text-ink-3">Source code</dt><dd className="break-all">{e.manifest.source_hash}</dd>
            <dt className="text-ink-3">Policy set</dt><dd className="break-all">{e.manifest.policy_set_hash}</dd>
            <dt className="text-ink-3">Risk model</dt><dd className="break-all">{model ? `${model.version} · ${model.bundle_sha256}` : "not used"}</dd>
            <dt className="text-ink-3">Seed / repeats</dt><dd>{e.manifest.seed} / {e.manifest.repeats}</dd>
            <dt className="text-ink-3">Environment</dt><dd className="break-all">Python {e.manifest.python} · {e.manifest.platform}</dd>
          </dl>
        </details>
      </Panel>

      <div role="tablist" aria-label="Experiment view" className="mb-4 flex gap-1 border-b border-line">
        {(["results", "scenarios"] as const).map((t) => (
          <button key={t} type="button" role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
            className={`-mb-px border-b-2 px-3 py-2 text-[13px] ${tab === t ? "border-accent font-medium" : "border-transparent text-ink-2"}`}>
            {t === "results" ? "Results" : "Scenarios"}
          </button>
        ))}
      </div>
      {tab === "results"
        ? (e.status === "completed" ? <Results experimentId={id} /> : <EmptyState title="Results appear when the experiment completes">{active ? "Runs are still in progress." : `This experiment ${e.status}.`}</EmptyState>)
        : <ScenarioMatrix id={id} active={active} total={e.total_runs} />}
      <ConfirmDialog open={confirming} title="Cancel this experiment?" confirmLabel="Cancel experiment" busy={cancelling}
        onConfirm={() => void cancel()} onCancel={() => setConfirming(false)}>
        Runs already finished are kept, but the experiment will be marked cancelled and will not produce results. This cannot be resumed.
      </ConfirmDialog>
    </>
  );
}
