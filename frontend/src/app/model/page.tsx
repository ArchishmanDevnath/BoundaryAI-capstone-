"use client";

import Link from "next/link";
import { useState } from "react";
import { RateBars } from "@/components/charts";
import { EmptyState, ErrorNotice, Loading, PageHeader, Panel, pct, shortTime, Status } from "@/components/ui";
import { usePoll, type EvalMetrics, type HeuristicComparison, type ModelInfo } from "@/lib/api";

const MODELS = [["hybrid", "Hybrid (deployed)"], ["structured", "Structured features"], ["text", "Text (TF-IDF)"], ["heuristic", "Heuristic baseline"]] as const;
const PROFILE_NAMES: Record<string, string> = { stateless: "Without history (configuration D)", stateful: "With history (configuration E)" };

function ci(range: [number, number] | null | undefined): string {
  return range ? `95% CI ${pct(range[0], 0)} to ${pct(range[1], 0)}` : "";
}

function MetricsTable({ metrics, caption }: { metrics: Record<string, EvalMetrics>; caption: string }) {
  return (
    <div className="overflow-x-auto">
      <table>
        <caption className="mb-2 text-left text-xs text-ink-3">{caption}</caption>
        <thead>
          <tr><th>Model</th><th className="text-right">PR-AUC</th><th className="text-right">Precision</th><th className="text-right">Recall</th><th className="text-right">F1</th>
            <th className="text-right">False positives</th><th className="text-right">False negatives</th><th className="text-right">Calibration error</th><th className="text-right">Threshold</th></tr>
        </thead>
        <tbody>
          {MODELS.map(([key, label]) => {
            const m = metrics[key];
            if (!m) return null;
            return (
              <tr key={key}>
                <td className="whitespace-nowrap">{label}</td>
                <td className="tnum text-right" title={ci(m.bootstrap_by_family?.pr_auc_ci95)}>{m.pr_auc?.toFixed(3) ?? "n/a"}</td>
                <td className="tnum text-right">{pct(m.precision)}</td>
                <td className="tnum text-right" title={ci(m.bootstrap_by_family?.recall_ci95)}>{pct(m.recall)}<span className="block text-[11px] text-ink-3">{m.confusion.tp}/{m.confusion.tp + m.confusion.fn}</span></td>
                <td className="tnum text-right">{m.f1.toFixed(3)}</td>
                <td className="tnum text-right" title={ci(m.bootstrap_by_family?.false_positive_rate_ci95)}>{pct(m.false_positive_rate)}<span className="block text-[11px] text-ink-3">{m.confusion.fp}/{m.confusion.fp + m.confusion.tn}</span></td>
                <td className="tnum text-right">{pct(m.false_negative_rate)}</td>
                <td className="tnum text-right">{m.ece.toFixed(3)}</td>
                <td className="tnum text-right">{m.threshold.toFixed(2)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function ModelPage() {
  const model = usePoll<ModelInfo>("/ml/model");
  const comparison = usePoll<HeuristicComparison>("/ml/heuristic-comparison");
  const [profile, setProfile] = useState("stateful");

  if (model.loading && !model.data) return <Loading />;
  if (!model.data) return <ErrorNotice error={model.error} />;
  const info = model.data;

  if (!info.available || !info.metadata) {
    return (
      <>
        <PageHeader title="Risk model" />
        <EmptyState title="No usable model is installed">
          {info.problem} Configurations D and E block every action they assess until a model is trained.
          Run <code className="font-mono text-xs">python scripts/prepare_data.py</code> and then <code className="font-mono text-xs">python scripts/train_models.py --final-test</code> in the backend folder.
        </EmptyState>
      </>
    );
  }
  const meta = info.metadata;
  const p = meta.profiles[profile];
  const top = Object.entries(p.structured_importances).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const maxImportance = top[0]?.[1] ?? 1;
  const byCategory = p.test?.hybrid.by_category ?? {};

  return (
    <>
      <PageHeader title="Risk model" description="The ML assessor used by configurations D and E. It can only tighten a decision, and it never sees an action the rules denied." />

      <div className="mb-4 rounded-md border border-line-strong bg-raised px-4 py-3 text-[13px]">
        <span aria-hidden className="mr-2 font-bold text-warn">!</span>
        {meta.interpretation} In the benchmarks, neither ML configuration outperformed rules + heuristic + history, so treat D and E as
        experimental. See the <Link href="/experiments" className="underline">experiments</Link> for end-to-end results.
      </div>

      <div className="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel title="Active model">
          <dl className="grid grid-cols-[7rem_1fr] gap-y-1.5 text-[13px]">
            <dt className="text-ink-3">Version</dt><dd className="break-all font-mono text-xs">{meta.version}</dd>
            <dt className="text-ink-3">Trained</dt><dd>{shortTime(meta.trained_at)}</dd>
            <dt className="text-ink-3">Integrity</dt><dd><Status tone="good" glyph="✓">Hashes verified</Status></dd>
            <dt className="text-ink-3">Test set</dt><dd>{meta.test_evaluated ? "Evaluated once" : "Not evaluated"}</dd>
            <dt className="text-ink-3">Libraries</dt><dd className="text-xs">{Object.entries(meta.library_versions).map(([k, v]) => `${k} ${v}`).join(", ")}</dd>
            <dt className="text-ink-3">Thresholds</dt><dd className="text-xs">{meta.config.threshold_rule}: false positives at most {pct(meta.config.review_max_fpr, 0)} for review and {pct(meta.config.block_max_fpr, 0)} for block, on validation.</dd>
          </dl>
        </Panel>
        <Panel title="Training data" subtitle="Generated BoundaryGuard actions with rule-based labels. Projects, tasks and behaviours never cross splits." className="lg:col-span-2">
          <div className="overflow-x-auto">
            <table>
              <thead><tr><th>Split</th><th className="text-right">Actions</th><th className="text-right">Unauthorized</th><th className="text-right">Legitimate</th><th className="text-right">Behaviour families</th><th>Projects</th></tr></thead>
              <tbody>
                {Object.entries(meta.data).map(([split, d]) => (
                  <tr key={split}>
                    <td className="capitalize">{split}</td>
                    <td className="tnum text-right">{d.records.toLocaleString()}</td>
                    <td className="tnum text-right">{d.unauthorized.toLocaleString()}</td>
                    <td className="tnum text-right">{d.legitimate.toLocaleString()}</td>
                    <td className="tnum text-right">{d.families}</td>
                    <td className="text-xs text-ink-2">{d.projects.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-xs text-ink-3">InjecAgent is not in this table on purpose. It is used only as an external test, through the experiments.</p>
        </Panel>
      </div>

      <div role="radiogroup" aria-label="Model profile" className="mb-4 flex w-fit flex-wrap rounded border border-line p-0.5">
        {Object.keys(meta.profiles).map((name) => (
          <button key={name} type="button" role="radio" aria-checked={profile === name} onClick={() => setProfile(name)}
            className={`rounded px-2.5 py-1 text-xs ${profile === name ? "bg-raised font-medium" : "text-ink-2"}`}>{PROFILE_NAMES[name] ?? name}</button>
        ))}
      </div>

      <Panel className="mb-4" title="Offline evaluation" subtitle={`Selected structured model: ${p.structured_selected.replace("_", " ")}. Hover a value for its 95% interval from resampling behaviour families.`}>
        {p.test ? <MetricsTable metrics={p.test} caption="Untouched native test split, evaluated once." /> : (
          <p className="mb-3 text-xs text-ink-3">
            This model was not evaluated on the test split. A model trained after the test groups have already been used for another model
            cannot get an untouched test result, so its evidence is validation (below) and the end-to-end experiments, which are labelled post-hoc.
          </p>
        )}
        <details className="mt-4">
          <summary className="cursor-pointer text-xs text-ink-3">Validation results, used for selection and thresholds</summary>
          <div className="mt-2"><MetricsTable metrics={p.validation} caption="Validation split. Optimistic, because it was used to choose models and thresholds." /></div>
        </details>
      </Panel>

      <div className={`mb-4 grid grid-cols-1 gap-4 ${p.test ? "xl:grid-cols-2" : ""}`}>
        <Panel title="What the structured model relies on" subtitle="Impurity-based importances. They show reliance, not causation.">
          <RateBars rows={top.map(([name, value]) => ({
            key: name, label: name.replaceAll("_", " "), value: value / maxImportance, color: "var(--color-accent)", right: value.toFixed(3),
            tip: `${name}: importance ${value.toFixed(4)}`,
          }))} />
        </Panel>
        {p.test && <Panel title="Test results by behaviour" subtitle="Hybrid model on the native test split">
          {Object.keys(byCategory).length === 0 ? <EmptyState title="No test evaluation recorded" /> : (
            <div className="overflow-x-auto">
              <table>
                <thead><tr><th>Behaviour</th><th className="text-right">Unauthorized caught</th><th className="text-right">Legitimate flagged</th></tr></thead>
                <tbody>
                  {Object.entries(byCategory).map(([name, c]) => (
                    <tr key={name}>
                      <td>{name.replaceAll("_", " ")}</td>
                      <td className="tnum text-right">{c.unauthorized ? `${c.caught}/${c.unauthorized}` : "-"}</td>
                      <td className="tnum text-right">{c.legitimate ? `${c.legitimate_flagged}/${c.legitimate}` : "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>}
      </div>

      <Panel title="Heuristic and ML on the same actions" subtitle={comparison.data?.experiment ? `Configuration C against D in ${comparison.data.experiment.name}, matched by scenario and step. Only actions the rules passed.` : undefined}>
        {!comparison.data?.experiment ? <EmptyState title="Run an experiment with C and D to compare them" /> : (
          <div className="overflow-x-auto">
            <table>
              <thead><tr><th>Ground truth</th><th>Heuristic</th><th>ML</th><th className="text-right">Actions</th></tr></thead>
              <tbody>
                {comparison.data.rows.map((r) => (
                  <tr key={`${r.label}-${r.heuristic}-${r.ml}`}>
                    <td>{r.label}</td><td>{r.heuristic}</td><td>{r.ml}</td>
                    <td className="tnum text-right">{r.actions.toLocaleString()}{r.heuristic !== r.ml && <span className="ml-2 text-xs text-ink-3">{(r.label === "unauthorized") === (r.ml === "stop") ? "ML right" : "heuristic right"}</span>}</td>
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
