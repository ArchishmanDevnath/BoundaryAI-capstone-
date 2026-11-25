"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import {
  Button, CATEGORY_NAMES, CONFIG_HELP, CONFIG_NAMES, CONFIG_ORDER, EmptyState, ErrorNotice, Field, PageHeader, Panel, RunStatus, shortTime, SuccessNotice,
} from "@/components/ui";
import { api, ApiError, usePoll, type Experiment, type Health, type Providers, type ScenarioSummary } from "@/lib/api";

const INTERNAL_CATEGORIES = ["benign", "prompt_injection", "permission_violation", "repeated_unnecessary"];
const EXTERNAL_CASES = 2125;

export default function ExperimentsPage() {
  const experiments = usePoll<Experiment[]>("/experiments", 2000);
  const providers = usePoll<Providers>("/providers");
  const scenarios = usePoll<ScenarioSummary[]>("/scenarios");
  const health = usePoll<Health>("/health", 5000);
  const modelReady = !!health.data?.ml_model?.available;

  const [name, setName] = useState("Benchmark run");
  const [suite, setSuite] = useState<"internal" | "injecagent">("internal");
  const [configs, setConfigs] = useState<string[]>(["A", "B", "RC", "C", "D", "E"]);
  const [categories, setCategories] = useState<string[]>(INTERNAL_CATEGORIES);
  const [split, setSplit] = useState("");
  const [agent, setAgent] = useState("scripted");
  const [repeats, setRepeats] = useState(1);
  const [seed, setSeed] = useState(0);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [started, setStarted] = useState<string | null>(null);

  const chosen = configs.filter((c) => modelReady || !["D", "E"].includes(c));
  const scripted = suite === "injecagent" || agent === "scripted";
  const selected = useMemo(() => suite === "injecagent"
    ? EXTERNAL_CASES
    : (scenarios.data ?? []).filter((s) => categories.includes(s.category) && (!split || s.split === split)).length, [scenarios.data, categories, split, suite]);
  const totalRuns = selected * chosen.length * (scripted ? 1 : repeats);
  const nameProblem = name.trim() ? null : "Give the experiment a name.";
  const repeatsProblem = !scripted && (!Number.isInteger(repeats) || repeats < 1 || repeats > 20) ? "Between 1 and 20." : null;
  const blocked = nameProblem ?? repeatsProblem ?? (chosen.length === 0 ? "Choose at least one configuration." : totalRuns === 0 ? "The filters select no scenarios." : null);

  function toggle(list: string[], value: string, set: (next: string[]) => void) {
    set(list.includes(value) ? list.filter((v) => v !== value) : [...list, value]);
  }

  async function start() {
    if (busy || blocked) return;
    setBusy(true);
    setError(null);
    setStarted(null);
    try {
      const body = suite === "injecagent"
        ? { name: name.trim(), suite, configurations: chosen, agent_provider: "scripted" }
        : { name: name.trim(), suite, configurations: chosen, categories, split: split || null, agent_provider: agent, repeats: scripted ? 1 : repeats, seed };
      const result = await api<{ experiment_id: string }>("/experiments", { method: "POST", body });
      setStarted(result.experiment_id);
      experiments.refresh();
    } catch (err) {
      setError(err as ApiError);
    } finally {
      setBusy(false);
    }
  }

  const agentInfo = providers.data?.agents.find((a) => a.id === agent);

  return (
    <>
      <PageHeader title="Experiments" description="Run a benchmark across configurations under identical conditions, then open it to compare results." />
      <ErrorNotice error={error ?? experiments.error} />
      {started && (
        <SuccessNotice message="Experiment started. It runs in the background and appears in the history below." onDismiss={() => setStarted(null)} />
      )}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[22rem_1fr]">
        <Panel title="New experiment">
          <div className="space-y-3">
            <Field label="Name" hint={nameProblem ?? undefined}><input value={name} onChange={(e) => setName(e.target.value)} maxLength={200} aria-invalid={nameProblem ? true : undefined} /></Field>
            <Field label="Benchmark" hint={suite === "injecagent" ? "2,108 adapted InjecAgent attack cases and 17 clean controls. About 0.1 s per run." : undefined}>
              <select value={suite} onChange={(e) => setSuite(e.target.value as "internal" | "injecagent")}>
                <option value="internal">Internal scenarios (53)</option>
                <option value="injecagent">InjecAgent, external ({EXTERNAL_CASES.toLocaleString()} cases)</option>
              </select>
            </Field>
            <fieldset>
              <legend className="mb-1 text-xs text-ink-2">Configurations</legend>
              <div className="space-y-1">
                {CONFIG_ORDER.map((c) => {
                  const unavailable = ["D", "E"].includes(c) && !modelReady;
                  return (
                    <label key={c} className="flex items-start gap-2 text-[13px]" title={CONFIG_HELP[c]}>
                      <input type="checkbox" className="mt-0.5" disabled={unavailable} checked={configs.includes(c) && !unavailable} onChange={() => toggle(configs, c, setConfigs)} />
                      <span>{CONFIG_NAMES[c]}{unavailable && <span className="block text-xs text-ink-3">Needs a trained model</span>}</span>
                    </label>
                  );
                })}
              </div>
            </fieldset>
            {suite === "internal" && (
              <>
                <fieldset>
                  <legend className="mb-1 text-xs text-ink-2">Scenario categories</legend>
                  <div className="space-y-1">
                    {INTERNAL_CATEGORIES.map((c) => (
                      <label key={c} className="flex items-center gap-2 text-[13px]">
                        <input type="checkbox" checked={categories.includes(c)} onChange={() => toggle(categories, c, setCategories)} />{CATEGORY_NAMES[c]}
                      </label>
                    ))}
                  </div>
                </fieldset>
                <Field label="Split" hint="Report the holdout split. The heuristic was tuned on dev.">
                  <select value={split} onChange={(e) => setSplit(e.target.value)}>
                    <option value="">All scenarios</option><option value="dev">Dev only</option><option value="holdout">Holdout only</option>
                  </select>
                </Field>
                <Field label="Agent" hint={agentInfo?.note}>
                  <select value={agent} onChange={(e) => setAgent(e.target.value)}>
                    {(providers.data?.agents ?? []).map((a) => <option key={a.id} value={a.id} disabled={!a.available}>{a.label}{a.available ? "" : " (offline)"}</option>)}
                  </select>
                </Field>
                {!scripted && (
                  <div className="grid grid-cols-2 gap-3">
                    <Field label="Repeats" hint={repeatsProblem ?? undefined}><input type="number" min={1} max={20} value={repeats} onChange={(e) => setRepeats(Number(e.target.value))} /></Field>
                    <Field label="Seed"><input type="number" value={seed} onChange={(e) => setSeed(Number(e.target.value))} /></Field>
                  </div>
                )}
              </>
            )}
            <div className="tnum text-xs text-ink-2">{selected.toLocaleString()} scenarios × {chosen.length} configurations{!scripted && repeats > 1 ? ` × ${repeats}` : ""} = {totalRuns.toLocaleString()} runs</div>
            <Button variant="primary" className="w-full" disabled={busy || blocked !== null} onClick={() => void start()}>
              {busy ? "Starting…" : "Run experiment"}
            </Button>
            {blocked && <p className="text-xs text-ink-3">{blocked}</p>}
          </div>
        </Panel>

        <Panel title="History">
          {experiments.data && experiments.data.length === 0 ? (
            <EmptyState title="No experiments yet">Configure one and run it. Results appear here as they are measured.</EmptyState>
          ) : (
            <div className="overflow-x-auto">
              <table>
                <thead><tr><th>Name</th><th>Benchmark</th><th>Status</th><th>Progress</th><th>Created</th></tr></thead>
                <tbody>
                  {(experiments.data ?? []).map((e) => {
                    const progress = e.total_runs ? e.completed_runs / e.total_runs : 0;
                    return (
                      <tr key={e.id} className="hover:bg-raised">
                        <td><Link className="underline-offset-2 hover:underline" href={`/experiments/${e.id}`}>{e.name}</Link>
                          <span className="block text-xs text-ink-3">{(e.config.configurations as string[] | undefined)?.length ?? 0} configurations{e.manifest.model ? ` · ${e.manifest.model.version}` : ""}</span></td>
                        <td className="text-xs text-ink-2">{e.manifest.suite === "injecagent" ? "InjecAgent" : "Internal"} · {e.manifest.agent_provider}</td>
                        <td><RunStatus status={e.status} /></td>
                        <td className="min-w-40">
                          <div className="h-1.5 rounded bg-raised"><div className="h-full rounded bg-accent" style={{ width: `${progress * 100}%` }} /></div>
                          <div className="tnum mt-0.5 text-xs text-ink-3">{e.completed_runs.toLocaleString()} / {e.total_runs.toLocaleString()}</div>
                        </td>
                        <td className="tnum whitespace-nowrap text-xs text-ink-2">{shortTime(e.created_at)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
