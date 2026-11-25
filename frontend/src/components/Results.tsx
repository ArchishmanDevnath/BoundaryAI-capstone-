"use client";

import { useState } from "react";
import { GroupedRateBars, RateBars } from "@/components/charts";
import {
  CATEGORY_NAMES, CONFIG_COLORS, CONFIG_NAMES, ConfigTag, EmptyState, ErrorNotice, latency, Loading, Panel, pct, SPLIT_NAMES,
} from "@/components/ui";
import { ApiError, usePoll, type Compare, type MetricRow } from "@/lib/api";

function fraction(row: MetricRow | null | undefined): string {
  return row?.numerator !== null && row?.numerator !== undefined && row.denominator ? `${row.numerator}/${row.denominator}` : "";
}

function ciText(row: MetricRow | null | undefined): string {
  if (!row || row.ci_low === null || row.ci_high === null) return "";
  return `${row.scenario_numerator}/${row.scenario_denominator} scenarios, 95% CI ${pct(row.ci_low, 0)} to ${pct(row.ci_high, 0)}`;
}

// One table carries every number. Charts show only the two trade-offs a reader needs to see at a glance.
const COLUMNS: { metric: string; label: string; kind?: "latency" | "score" }[] = [
  { metric: "unauthorized_execution_rate", label: "Unauthorized executed" },
  { metric: "attack_prevention_rate", label: "Prevention (recall)" },
  { metric: "false_block_rate", label: "False blocks" },
  { metric: "legitimate_task_success", label: "Benign task success" },
  { metric: "precision", label: "Precision" },
  { metric: "f1", label: "F1" },
  { metric: "pr_auc", label: "PR-AUC", kind: "score" },
  { metric: "decision_latency_mean_us", label: "Mean latency", kind: "latency" },
  { metric: "policy_bypass_rate", label: "Policy bypass" },
  { metric: "audit_coverage", label: "Audit coverage" },
  { metric: "repeated_violation_handling", label: "Retry handling" },
];

function Cell({ row, kind }: { row: MetricRow | undefined; kind?: "latency" | "score" }) {
  if (!row || row.value === null) {
    return <td className="tnum text-right text-ink-3" title={(row?.extra?.note as string) ?? "No applicable actions"}>n/a</td>;
  }
  if (kind === "latency") return <td className="tnum text-right">{latency(row.value)}</td>;
  if (kind === "score") return <td className="tnum text-right" title={`${row.denominator} scored actions`}>{row.value.toFixed(3)}</td>;
  return (
    <td className="tnum text-right" title={ciText(row)}>
      {pct(row.value)}<span className="block text-[11px] text-ink-3">{fraction(row)}</span>
    </td>
  );
}

export default function Results({ experimentId }: { experimentId: string }) {
  const [split, setSplit] = useState<string | null>(null);
  const first = usePoll<Compare>(`/analytics/compare?experiment_id=${experimentId}&split=all`);
  const preferred = first.data?.splits.includes("external") ? "external" : first.data?.splits.includes("holdout") ? "holdout" : "all";
  const active = split ?? preferred;
  const compare = usePoll<Compare>(first.data ? `/analytics/compare?experiment_id=${experimentId}&split=${active}` : null);

  if (first.loading && !first.data) return <Loading />;
  if (!first.data) return <ErrorNotice error={first.error} />;
  const data = compare.data;
  const options = ["all", ...first.data.splits];
  const configs = data?.configurations.map((c) => c.id) ?? [];
  const kpis = Object.fromEntries((data?.kpis ?? []).map((k) => [k.metric, k]));
  const external = active === "external";

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div role="radiogroup" aria-label="Split" className="flex flex-wrap rounded border border-line p-0.5">
          {options.map((s) => (
            <button key={s} type="button" role="radio" aria-checked={active === s} onClick={() => setSplit(s)}
              className={`rounded px-2.5 py-1 text-xs ${active === s ? "bg-raised font-medium" : "text-ink-2"}`}>{SPLIT_NAMES[s] ?? s}</button>
          ))}
        </div>
        <p className="text-xs text-ink-3">
          {active === "dev" && "The heuristic was tuned on these scenarios, so these results are optimistic."}
          {active === "holdout" && "Not used for tuning. The heuristic author also wrote these scenarios, so treat them as an internal check."}
          {active === "external" && "InjecAgent cases, never used for training, tuning, calibration or threshold selection."}
          {active === "all" && "Mixes tuned and untuned scenarios. Prefer a held-out split when reporting."}
        </p>
      </div>
      <ErrorNotice error={compare.error instanceof ApiError && compare.error.status === 404 ? null : compare.error} />
      {!data ? <Loading /> : data.configurations.length === 0 ? <EmptyState title="No runs in this split" /> : (
        <>
          <Panel className="mb-4" title="Results by configuration" subtitle="Rates count actions. Hover a value for its confidence interval over scenarios. n/a means the metric does not apply.">
            <div className="overflow-x-auto">
              <table>
                <thead>
                  <tr><th>Configuration</th>{COLUMNS.map((c) => <th key={c.metric} className="whitespace-normal text-right align-bottom">{c.label}</th>)}</tr>
                </thead>
                <tbody>
                  {configs.map((c) => (
                    <tr key={c}>
                      <td className="whitespace-nowrap"><ConfigTag id={c} /></td>
                      {COLUMNS.map((col) => <Cell key={col.metric} row={data.overall[col.metric]?.[c]} kind={col.kind} />)}
                    </tr>
                  ))}
                  <tr className="text-xs text-ink-3">
                    <td>Proposal target (a goal)</td>
                    {COLUMNS.map((col) => <td key={col.metric} className="text-right">{kpis[col.metric]?.target_label ?? ""}</td>)}
                  </tr>
                </tbody>
              </table>
            </div>
          </Panel>

          <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
            <Panel title="Attacks stopped" subtitle="Unauthorized actions blocked out of those attempted">
              <RateBars target={kpis.attack_prevention_rate?.target} targetLabel={kpis.attack_prevention_rate?.target_label}
                rows={configs.map((c) => {
                  const row = data.overall.attack_prevention_rate?.[c];
                  return { key: c, label: CONFIG_NAMES[c], value: row?.value ?? null, color: CONFIG_COLORS[c], right: row?.value === null || row?.value === undefined ? "n/a" : pct(row.value),
                    tip: <span><b>{CONFIG_NAMES[c]}</b>: {fraction(row)} actions<br />{ciText(row)}</span> };
                })} />
            </Panel>
            <Panel title="Legitimate actions blocked" subtitle="The cost of the protection. Lower is better.">
              <RateBars target={kpis.false_block_rate?.target} targetLabel={kpis.false_block_rate?.target_label}
                rows={configs.filter((c) => c !== "A").map((c) => {
                  const row = data.overall.false_block_rate?.[c];
                  return { key: c, label: CONFIG_NAMES[c], value: row?.value ?? null, color: CONFIG_COLORS[c], right: row?.value === null || row?.value === undefined ? "n/a" : pct(row.value),
                    tip: <span><b>{CONFIG_NAMES[c]}</b>: {fraction(row)} legitimate actions<br />{ciText(row)}</span> };
                })} />
              {external && <p className="mt-2 text-xs text-ink-3">InjecAgent has 17 distinct user tasks, so this rate rests on a small, repeated set of legitimate actions.</p>}
            </Panel>
          </div>

          <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
            <Panel title="Attacks stopped by category">
              {(() => {
                const rows = Object.entries(data.categories).filter(([k]) => k !== "benign").map(([category, metrics]) => ({
                  group: CATEGORY_NAMES[category] ?? category,
                  values: configs.map((c) => {
                    const row = metrics.attack_prevention_rate?.[c];
                    return { config: c, value: row?.value ?? null, numerator: row?.numerator ?? null, denominator: row?.denominator ?? null };
                  }),
                }));
                return rows.length ? <GroupedRateBars rows={rows} /> : <EmptyState title="No attack scenarios in this selection" />;
              })()}
            </Panel>

            <Panel title="Are the differences real?" subtitle={external
              ? "Bootstrap over the attacker cases (2,000 resamples). Each case is replayed with the same 17 user tasks, so cases are clustered."
              : "Exact McNemar test with scenarios as the unit. Few disagreeing scenarios mean low power."}>
              {external ? (
                data.cluster_comparisons.length === 0 ? <EmptyState title="Needs two comparable configurations" /> : (
                  <div className="overflow-x-auto">
                    <table>
                      <thead><tr><th>Comparison</th><th className="whitespace-normal text-right">Prevention change</th><th className="whitespace-normal text-right">False-block change</th></tr></thead>
                      <tbody>
                        {data.cluster_comparisons.map((s) => (
                          <tr key={`${s.first}-${s.second}`}>
                            <td className="text-xs">{CONFIG_NAMES[s.second]} vs {CONFIG_NAMES[s.first]}</td>
                            <td className="tnum text-right text-xs">{signed(s.prevention_difference)}<span className="block text-ink-3">{ci(s.prevention_ci95)}</span></td>
                            <td className="tnum text-right text-xs">{s.false_block_difference === 0 && s.false_block_ci95?.[0] === 0 && s.false_block_ci95?.[1] === 0
                              ? <span className="text-ink-3">no change</span>
                              : <>{signed(s.false_block_difference)}<span className="block text-ink-3">{ci(s.false_block_ci95)}</span></>}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )
              ) : data.significance.length === 0 ? <EmptyState title="Needs two comparable guarded configurations" /> : (
                <div className="overflow-x-auto">
                  <table>
                    <thead><tr><th>Comparison</th><th>Outcome</th><th className="text-right">Only first</th><th className="text-right">Only second</th><th className="text-right">p</th></tr></thead>
                    <tbody>
                      {data.significance.map((s) => (
                        <tr key={`${s.first}-${s.second}-${s.outcome}`}>
                          <td className="whitespace-nowrap text-xs">{CONFIG_NAMES[s.first]} vs {CONFIG_NAMES[s.second]}</td>
                          <td className="text-xs text-ink-2">{s.outcome}</td>
                          <td className="tnum text-right">{s.only_first}</td>
                          <td className="tnum text-right">{s.only_second}</td>
                          <td className="tnum text-right">{s.p_value < 0.001 ? "<0.001" : s.p_value.toFixed(3)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>
          </div>

          <p className="text-xs text-ink-3">
            Configurations can attempt different numbers of actions, because a block or a safe termination changes what happens next.
            A zero observed rate does not prove an attack is impossible: conclusions are limited to these tools, policies and scenarios.
            Errored runs: {configs.map((c) => `${CONFIG_NAMES[c].split(" ·")[0]} ${data.overall.errored_runs?.[c]?.value ?? 0}`).join(", ")}.
            Unlabeled actions: {configs.map((c) => `${CONFIG_NAMES[c].split(" ·")[0]} ${data.overall.unlabeled_actions?.[c]?.value ?? 0}`).join(", ")}.
            Assessor failures (fail-closed): {configs.map((c) => `${CONFIG_NAMES[c].split(" ·")[0]} ${data.overall.assessor_fallbacks?.[c]?.value ?? 0}`).join(", ")}.
          </p>
        </>
      )}
    </>
  );
}

function signed(value: number | null): string {
  if (value === null) return "n/a";
  const points = value * 100;
  return `${points > 0 ? "+" : ""}${points.toFixed(1)} pts`;
}

function ci(range: [number, number] | null): string {
  return range ? `CI ${(range[0] * 100).toFixed(1)} to ${(range[1] * 100).toFixed(1)}` : "";
}
