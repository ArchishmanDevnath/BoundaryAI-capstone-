"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import {
  actionTarget, Button, CONFIG_HELP, CONFIG_NAMES, CONFIG_ORDER, ConfigTag, EmptyState, ErrorNotice, Field, PageHeader, Panel, RiskBadge, RunStatus, shortTime,
} from "@/components/ui";
import { api, ApiError, usePoll, type Approval, type Health, type PolicyRow, type Providers, type Run, type ScenarioSummary } from "@/lib/api";

const RECOMMENDED = "C";

export default function TraceIndexPage() {
  const router = useRouter();
  const scenarios = usePoll<ScenarioSummary[]>("/scenarios");
  const providers = usePoll<Providers>("/providers");
  const policies = usePoll<PolicyRow[]>("/policies");
  const runs = usePoll<{ total: number; items: Run[] }>("/runs?live_only=true&limit=30", 3000);
  const health = usePoll<Health>("/health", 5000);
  const approvals = usePoll<Approval[]>("/approvals", 3000);

  const [mode, setMode] = useState<"scenario" | "custom">("scenario");
  const [scenarioId, setScenarioId] = useState("pi01_readme_env_exfil");
  const [objective, setObjective] = useState("Fix the add function in src/calc.py so it adds.");
  const [fixture, setFixture] = useState("calc_lib");
  const [policyId, setPolicyId] = useState("benchmark:project_standard");
  const [configuration, setConfiguration] = useState(RECOMMENDED);
  const [agent, setAgent] = useState("scripted");
  const [assessor, setAssessor] = useState("heuristic");
  const [approval, setApproval] = useState("human");
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  const llmAgents = providers.data?.agents.filter((a) => a.id !== "scripted" && a.available) ?? [];
  const effectiveAgent = mode === "custom" && agent === "scripted" ? (llmAgents[0]?.id ?? "ollama") : agent;
  const customPossible = llmAgents.length > 0;
  const usesHeuristicSlot = configuration === "RC" || configuration === "C";

  async function start() {
    setBusy(true);
    setError(null);
    try {
      const body = mode === "scenario"
        ? { scenario_id: scenarioId }
        : { objective, fixture, policy_id: policyId };
      const result = await api<{ run_id: string }>("/runs", {
        method: "POST",
        body: { ...body, configuration, agent_provider: effectiveAgent, assessor: usesHeuristicSlot ? assessor : "heuristic", approval_mode: approval, step_delay_ms: 500 },
      });
      router.push(`/trace/${result.run_id}`);
    } catch (err) {
      setError(err as ApiError);
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Live runs" description="Start a run and watch each proposed action get a decision before anything executes. Open any run to inspect its decisions." />
      <ErrorNotice error={error ?? scenarios.error} />
      {(approvals.data?.length ?? 0) > 0 && (
        <Panel className="mb-4 border-warn" title="Waiting for your decision" subtitle="These actions are paused until you approve or deny them. Open one to see why it was escalated.">
          <ul className="divide-y divide-line">
            {approvals.data!.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-3 py-2 first:pt-0 last:pb-0">
                <span className="font-mono text-xs font-semibold">{a.tool}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-ink-2" title={actionTarget(a.args)}>{actionTarget(a.args)}</span>
                <RiskBadge level={a.risk_level} />
                <span className="text-xs text-ink-3">{shortTime(a.created_at)}</span>
                <Link href={`/trace/${a.run_id}`} className="text-xs font-medium underline">Review</Link>
              </li>
            ))}
          </ul>
        </Panel>
      )}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[22rem_1fr]">
        <Panel title="Start a live run">
          <div className="space-y-3">
            <div role="radiogroup" aria-label="Run source" className="flex gap-1 rounded border border-line p-0.5">
              {(["scenario", "custom"] as const).map((m) => (
                <button key={m} type="button" role="radio" aria-checked={mode === m} onClick={() => setMode(m)} disabled={m === "custom" && !customPossible}
                  title={m === "custom" && !customPossible ? "Needs a running LLM. Scripted runs can only replay benchmark scenarios." : undefined}
                  className={`flex-1 rounded px-2 py-1 text-xs disabled:opacity-50 ${mode === m ? "bg-raised font-medium" : "text-ink-2"}`}>
                  {m === "scenario" ? "Benchmark scenario" : "Custom task (LLM)"}
                </button>
              ))}
            </div>

            {mode === "scenario" ? (
              <Field label="Scenario">
                <select value={scenarioId} onChange={(e) => setScenarioId(e.target.value)}>
                  {(scenarios.data ?? []).map((s) => <option key={s.id} value={s.id}>{s.id}: {s.title}</option>)}
                </select>
              </Field>
            ) : (
              <>
                <Field label="Objective"><textarea rows={3} value={objective} onChange={(e) => setObjective(e.target.value)} /></Field>
                <Field label="Project fixture">
                  <select value={fixture} onChange={(e) => setFixture(e.target.value)}>
                    {(providers.data?.fixtures ?? []).map((f) => <option key={f}>{f}</option>)}
                  </select>
                </Field>
                <Field label="Policy">
                  <select value={policyId} onChange={(e) => setPolicyId(e.target.value)}>
                    {(policies.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.name} (v{p.version})</option>)}
                  </select>
                </Field>
              </>
            )}

            <Field label="Configuration" hint={CONFIG_HELP[configuration] + (["D", "E"].includes(configuration) && !health.data?.ml_model?.available ? " No model is installed, so it will block every assessed action." : "")}>
              <select value={configuration} onChange={(e) => setConfiguration(e.target.value)}>
                {CONFIG_ORDER.map((c) => <option key={c} value={c}>{CONFIG_NAMES[c]}{c === RECOMMENDED ? " (recommended)" : ""}</option>)}
              </select>
            </Field>
            <Field label="Agent">
              <select value={effectiveAgent} onChange={(e) => setAgent(e.target.value)}>
                {(providers.data?.agents ?? []).filter((a) => mode === "scenario" || a.id !== "scripted").map((a) => (
                  <option key={a.id} value={a.id}>{a.label}{a.available ? "" : " (offline)"}</option>
                ))}
              </select>
            </Field>
            {usesHeuristicSlot && (
              <Field label="Contextual assessor">
                <select value={assessor} onChange={(e) => setAssessor(e.target.value)}>
                  {(providers.data?.assessors ?? []).map((a) => <option key={a.id} value={a.id}>{a.label}{a.available ? "" : " (offline: uses fail-safe)"}</option>)}
                </select>
              </Field>
            )}
            <Field label="When approval is required">
              <select value={approval} onChange={(e) => setApproval(e.target.value)}>
                <option value="human">Wait for me in the trace</option>
                <option value="auto_deny">Deny automatically</option>
              </select>
            </Field>
            <Button variant="primary" className="w-full" disabled={busy} onClick={() => void start()}>
              {busy ? "Starting…" : "Start run"}
            </Button>
          </div>
        </Panel>

        <Panel title="Live runs" subtitle="Runs that belong to an experiment are on the experiment's page.">
          {runs.data && runs.data.items.length === 0 ? (
            <EmptyState title="No live runs yet">Start one to see its trace here.</EmptyState>
          ) : (
            <div className="overflow-x-auto">
              <table>
                <thead><tr><th>Started</th><th>Task</th><th>Configuration</th><th>Status</th><th className="text-right" title="Actions the guard stopped, out of all actions the agent proposed">Stopped</th></tr></thead>
                <tbody>
                  {(runs.data?.items ?? []).map((r) => (
                    <tr key={r.id} className="hover:bg-raised">
                      <td className="tnum whitespace-nowrap text-xs text-ink-2">{shortTime(r.started_at)}</td>
                      <td className="max-w-80"><Link href={`/trace/${r.id}`} className="underline-offset-2 hover:underline">
                        <span className="block truncate font-mono text-xs">{r.scenario_id ?? "custom task"}</span>
                        <span className="block truncate text-xs text-ink-3">{r.objective}</span>
                      </Link></td>
                      <td><ConfigTag id={r.configuration} /></td>
                      <td><RunStatus status={r.status} reason={r.termination_reason} /></td>
                      <td className="tnum whitespace-nowrap text-right">{r.blocked_actions ?? 0} of {r.step_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
