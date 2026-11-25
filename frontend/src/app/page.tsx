"use client";

import Link from "next/link";
import {
  actionTarget, CONFIG_NAMES, CONFIG_ORDER, ConfigTag, DecisionBadge, EmptyState, ErrorNotice, Loading, PageHeader,
  Panel, pct, Provenance, shortTime, SPLIT_NAMES, Status,
} from "@/components/ui";
import { usePoll, type Overview } from "@/lib/api";

/** The breakdown shows the newest experiments; older ones are summed into one row so the parts still add up to the total. */
const RECENT_EXPERIMENTS = 3;

const HEADLINE = [
  ["attack_prevention_rate", "Attacks stopped"],
  ["false_block_rate", "Legitimate actions blocked"],
  ["legitimate_task_success", "Benign tasks completed"],
] as const;

export default function OverviewPage() {
  const { data, error, loading } = usePoll<Overview>("/overview", 4000);

  if (loading && !data) return <Loading />;
  if (!data) return <ErrorNotice error={error} />;

  const { runs, health, latest_experiment: latest, latest_metrics: metrics } = data;
  // Headline numbers come from the split that played no part in tuning, when the experiment has one.
  const splits = new Set(metrics.map((m) => m.split));
  const split = splits.has("external") ? "external" : splits.has("holdout") ? "holdout" : "all";
  const metric = (config: string, name: string) => metrics.find((m) => m.configuration === config && m.metric === name && m.split === split);
  const configs = CONFIG_ORDER.filter((c) => metrics.some((m) => m.configuration === c));
  const integrity = data.audit_integrity;

  return (
    <>
      <PageHeader title="Security overview" description="System status, the latest measured results and recent decisions. Every value is read from stored records." />
      <ErrorNotice error={error} />

      <div className="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel title="System status">
          <ul className="space-y-2 text-[13px]">
            <li className="flex justify-between gap-3">Deterministic rules
              {health.deterministic_guard && health.database ? <Status tone="good" glyph="●">Enforcing</Status> : <Status tone="critical" glyph="!">Down</Status>}
            </li>
            <li className="flex justify-between gap-3">ML risk model
              {health.ml_model?.available
                ? <Link href="/model" className="font-mono text-xs underline-offset-2 hover:underline">{health.ml_model?.version}</Link>
                : <Status tone="warn" glyph="○">Missing: D and E fail closed</Status>}
            </li>
            <li className="flex justify-between gap-3">Ollama
              {health.llm.ollama ? <Status tone="good" glyph="●">Available</Status> : <Status tone="neutral" glyph="○">Not running</Status>}
            </li>
            <li className="flex justify-between gap-3">Audit chains
              <span className="tnum text-xs text-ink-2">{integrity.runs_checked ? `${integrity.runs_valid} of ${integrity.runs_checked} recent runs verify` : "Nothing to verify yet"}</span>
            </li>
            <li className="flex justify-between gap-3">Waiting for approval
              {data.approvals_pending ? <Link href="/trace" className="text-xs underline"><Status tone="warn" glyph="?">{data.approvals_pending} pending</Status></Link> : <span className="text-xs text-ink-3">None</span>}
            </li>
          </ul>
          {data.human_overrides > 0 && (
            <p className="mt-3 border-t border-line pt-3 text-xs text-ink-2">
              <span aria-hidden className="mr-1 font-bold text-warn">!</span>
              {data.human_overrides} action{data.human_overrides === 1 ? " was" : "s were"} approved by a person although the scenario labels {data.human_overrides === 1 ? "it" : "them"} unauthorized.
              <Link href="/audit?gt_label=unauthorized" className="ml-1 underline">Review</Link>
            </p>
          )}
        </Panel>

        <Panel title="Recorded runs" subtitle="Each run belongs to one experiment or is a live run, so the parts add up to the total." className="lg:col-span-2">
          {runs.total === 0 ? (
            <EmptyState title="Nothing has run yet"><Link className="underline" href="/experiments">Run an experiment</Link> or start a <Link className="underline" href="/trace">live run</Link>.</EmptyState>
          ) : (
            <div className="overflow-x-auto">
              <table>
                <thead><tr><th>Source</th><th>Status</th><th className="text-right">Runs</th></tr></thead>
                <tbody>
                  {runs.by_experiment.slice(0, RECENT_EXPERIMENTS).map((e) => (
                    <tr key={e.id}>
                      <td><Link href={`/experiments/${e.id}`} className="underline-offset-2 hover:underline">{e.name}</Link><span className="ml-2 text-xs text-ink-3">{shortTime(e.created_at)}</span></td>
                      <td className="text-xs text-ink-2">{e.status}</td>
                      <td className="tnum text-right">{e.recorded_runs.toLocaleString()}{e.recorded_runs !== e.total_runs && <span className="text-ink-3"> of {e.total_runs.toLocaleString()}</span>}</td>
                    </tr>
                  ))}
                  {runs.by_experiment.length > RECENT_EXPERIMENTS && (
                    <tr>
                      <td><Link href="/experiments" className="underline-offset-2 hover:underline">
                        {runs.by_experiment.length - RECENT_EXPERIMENTS} earlier experiment{runs.by_experiment.length - RECENT_EXPERIMENTS === 1 ? "" : "s"}
                      </Link></td>
                      <td />
                      <td className="tnum text-right">{runs.by_experiment.slice(RECENT_EXPERIMENTS).reduce((sum, e) => sum + e.recorded_runs, 0).toLocaleString()}</td>
                    </tr>
                  )}
                  <tr><td><Link href="/trace" className="underline-offset-2 hover:underline">Live runs</Link></td><td /><td className="tnum text-right">{runs.live_runs.toLocaleString()}</td></tr>
                  <tr className="font-semibold"><td>Total</td><td /><td className="tnum text-right">{runs.total.toLocaleString()}</td></tr>
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>

      <Panel
        className="mb-4"
        title="Latest experiment"
        subtitle={latest ? `${latest.name} · finished ${shortTime(latest.finished_at)} · ${SPLIT_NAMES[split]} results` : undefined}
        actions={latest && <Link href={`/experiments/${latest.id}`} className="text-xs underline">Full results</Link>}
      >
        {!latest ? (
          <EmptyState title="No completed experiments"><Link className="underline" href="/experiments">Start one</Link> to see measured results here.</EmptyState>
        ) : (
          <>
            <Provenance provider={latest.manifest.agent_provider} note={latest.manifest.provenance} />
            <div className="overflow-x-auto">
              <table>
                <thead><tr><th>Configuration</th>{HEADLINE.map(([m, label]) => <th key={m} className="text-right">{label}</th>)}</tr></thead>
                <tbody>
                  {configs.map((c) => (
                    <tr key={c}>
                      <td><ConfigTag id={c} />{c === "C" && <span className="ml-2 text-xs text-ink-3">recommended</span>}</td>
                      {HEADLINE.map(([m]) => {
                        const row = metric(c, m);
                        return (
                          <td key={m} className="tnum text-right">
                            {pct(row?.value)}
                            {row?.denominator ? <span className="block text-[11px] text-ink-3">{row.numerator}/{row.denominator}</span> : null}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Panel>

      <Panel title="Recent stopped actions" subtitle="Guarded configurations only. The unprotected baseline never stops anything." actions={<Link href="/audit" className="text-xs underline">Audit log</Link>}>
        {data.recent_events.length === 0 ? (
          <EmptyState title="No stopped actions yet" />
        ) : (
          <div className="overflow-x-auto">
            <table>
              <thead><tr><th>Time</th><th>Decision</th><th>Action</th><th>Configuration</th><th>Reason</th></tr></thead>
              <tbody>
                {data.recent_events.map((e) => (
                  <tr key={e.action_id}>
                    <td className="tnum whitespace-nowrap text-xs text-ink-2">{shortTime(e.decided_at)}</td>
                    <td><DecisionBadge decision={e.final_decision} approval={e.approval_outcome} /></td>
                    <td className="max-w-64">
                      <Link href={`/trace/${e.run_id}`} className="underline-offset-2 hover:underline">
                        <span className="font-mono text-xs">{e.tool}</span>
                        <span className="block truncate font-mono text-xs text-ink-3">{actionTarget(e.args)}</span>
                      </Link>
                    </td>
                    <td><span title={CONFIG_NAMES[e.configuration]}><ConfigTag id={e.configuration} /></span></td>
                    <td className="max-w-96 text-xs text-ink-2">{e.rule_id && <code className="mr-1 font-mono">{e.rule_id}</code>}{e.reasoning}</td>
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
