"use client";

import { useEffect, useMemo, useState } from "react";
import { ConfirmDialog } from "@/components/Confirm";
import { Button, EmptyState, ErrorNotice, Field, Loading, PageHeader, Panel, shortTime, Status, SuccessNotice } from "@/components/ui";
import { api, ApiError, usePoll, type Policy, type PolicyRow, type Tool } from "@/lib/api";

const lines = (value: string) => value.split("\n").map((s) => s.trim()).filter(Boolean);
const NAME = /^[A-Za-z0-9][A-Za-z0-9 ._-]*$/;
const HOST = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
const IP = /^(\d{1,3}(\.\d{1,3}){3}|\[?[0-9a-f:]+\]?)$/i;
const METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];
const LIMITS = {
  max_steps: [1, 500], max_calls_per_tool: [1, 500], max_write_bytes: [1, Number.MAX_SAFE_INTEGER], same_action_denials: [1, 50], total_denials: [1, 200],
} as const;

/** The same rules the backend applies, so mistakes show up while typing. The backend still validates every save. */
function validate(name: string, body: Policy, needsName: boolean): Record<string, string> {
  const problems: Record<string, string> = {};
  const trimmed = name.trim();
  if (needsName) {
    if (!trimmed) problems.name = "Give the policy a name.";
    else if (trimmed.length > 80) problems.name = "At most 80 characters.";
    else if (!NAME.test(trimmed)) problems.name = "Use unaccented letters (A–Z), digits, spaces, dots, dashes or underscores, starting with a letter or digit.";
  }
  for (const field of ["read_paths", "write_paths", "protected_paths", "approval_paths"] as const) {
    const bad = body[field].find((p) => !p.startsWith("/") && !p.startsWith("**"));
    if (bad) problems[field] = `'${bad}' must start with / (for example /project/src/**) or ** (for example **/.env*).`;
  }
  const badHost = body.network.allowed_hosts.find((h) => IP.test(h) || !HOST.test(h));
  if (badHost) problems.hosts = IP.test(badHost) ? `'${badHost}' is an IP address. IP addresses are always refused.` : `'${badHost}' is not a host name. Lower case, no https:// or path.`;
  const badMethod = body.network.allowed_methods.find((m) => !METHODS.includes(m));
  if (badMethod) problems.methods = `'${badMethod}' is not supported. Use ${METHODS.join(", ")}.`;
  const numbers: [keyof typeof LIMITS, number][] = [
    ["max_steps", body.limits.max_steps], ["max_calls_per_tool", body.limits.max_calls_per_tool], ["max_write_bytes", body.limits.max_write_bytes],
    ["same_action_denials", body.retry.same_action_denials], ["total_denials", body.retry.total_denials],
  ];
  for (const [key, value] of numbers) {
    const [low, high] = LIMITS[key];
    if (!Number.isInteger(value) || value < low || value > high) problems[key] = high > 1e9 ? `At least ${low}.` : `Between ${low} and ${high}.`;
  }
  return problems;
}

function ListField({ label, hint, value, onChange, disabled, error }: {
  label: string; hint?: string; value: string[]; onChange: (next: string[]) => void; disabled: boolean; error?: string;
}) {
  // Keep raw text while typing, so a half-finished line is not stripped out.
  const [text, setText] = useState(value.join("\n"));
  return (
    <Field label={label} hint={error ?? hint}>
      <textarea rows={Math.max(3, Math.min(8, value.length + 1))} className="font-mono text-xs" value={text} disabled={disabled}
        aria-invalid={error ? true : undefined} style={error ? { borderColor: "var(--color-critical)" } : undefined}
        onChange={(e) => { setText(e.target.value); onChange(lines(e.target.value)); }} />
    </Field>
  );
}

function NumberField({ label, value, onChange, disabled, error }: { label: string; value: number; onChange: (n: number) => void; disabled: boolean; error?: string }) {
  return (
    <Field label={label} hint={error}>
      <input type="number" min={1} step={1} value={Number.isNaN(value) ? "" : value} disabled={disabled} aria-invalid={error ? true : undefined}
        style={error ? { borderColor: "var(--color-critical)" } : undefined}
        onChange={(e) => onChange(e.target.value === "" ? Number.NaN : Number(e.target.value))} />
    </Field>
  );
}

type Saved = { row: PolicyRow; message: string };

function PolicyEditor({ row, tools, isNew, onSaved, onDeactivated, onDirtyChange }: {
  row: PolicyRow; tools: Tool[]; isNew: boolean; onSaved: (saved: Saved) => void; onDeactivated: (name: string) => void; onDirtyChange: (dirty: boolean) => void;
}) {
  const [name, setName] = useState(isNew ? `${row.name}-custom` : row.name);
  const [body, setBody] = useState<Policy>(row.body);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const locked = (row.read_only || !row.active) && !isNew;

  const dirty = useMemo(() => isNew || JSON.stringify(body) !== JSON.stringify(row.body), [body, row.body, isNew]);
  const problems = useMemo(() => (locked ? {} : validate(name, body, isNew)), [name, body, isNew, locked]);
  const invalid = Object.keys(problems).length > 0;
  // A copy counts as unsaved work from the start; an edit only once something differs from the stored version.
  useEffect(() => { onDirtyChange(!locked && dirty); }, [dirty, locked, onDirtyChange]);

  const set = <K extends keyof Policy>(key: K, value: Policy[K]) => setBody((b) => ({ ...b, [key]: value }));

  function toolState(tool: string): string {
    if (body.prohibited_tools.includes(tool)) return "prohibited";
    if (body.approval_tools.includes(tool)) return "approval";
    return body.allowed_tools.includes(tool) ? "allowed" : "off";
  }

  function setToolState(tool: string, state: string) {
    const without = (list: string[]) => list.filter((t) => t !== tool);
    setBody((b) => ({
      ...b,
      allowed_tools: state === "allowed" || state === "approval" ? [...without(b.allowed_tools), tool] : without(b.allowed_tools),
      approval_tools: state === "approval" ? [...without(b.approval_tools), tool] : without(b.approval_tools),
      prohibited_tools: state === "prohibited" ? [...without(b.prohibited_tools), tool] : without(b.prohibited_tools),
    }));
  }

  async function save() {
    if (busy || invalid) return;
    setBusy(true);
    setError(null);
    try {
      const trimmed = name.trim();
      const saved = isNew
        ? await api<PolicyRow>("/policies", { method: "POST", body: { name: trimmed, body: { ...body, name: trimmed } } })
        : await api<PolicyRow>(`/policies/${row.id}`, { method: "PUT", body: { name: row.name, body } });
      onSaved({ row: saved, message: isNew ? `Created policy "${saved.name}".` : `Saved "${saved.name}" as version ${saved.version}.` });
    } catch (err) {
      setError(err as ApiError);
      setBusy(false);
    }
  }

  async function deactivate() {
    setBusy(true);
    setError(null);
    try {
      await api(`/policies/${row.id}`, { method: "DELETE" });
      setConfirming(false);
      onDeactivated(row.name);
    } catch (err) {
      setError(err as ApiError);
      setConfirming(false);
      setBusy(false);
    }
  }

  return (
    <>
      <ErrorNotice error={error} />
      {isNew && (
        <div className="mb-4 w-full max-w-sm">
          <Field label="Policy name" hint={problems.name ?? "Must be unique. Benchmark policy names are reserved."}>
            <input value={name} maxLength={80} onChange={(e) => setName(e.target.value)} aria-invalid={problems.name ? true : undefined}
              style={problems.name ? { borderColor: "var(--color-critical)" } : undefined} />
          </Field>
        </div>
      )}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Tools" subtitle="Prohibited always wins. All tools are simulated: none can reach a real process or network.">
          {tools.length === 0 ? <EmptyState title="The tool list could not be loaded" /> : (
            <table>
              <tbody>
                {tools.map((tool) => (
                  <tr key={tool.name}>
                    <td>
                      <code className="font-mono text-xs">{tool.name}</code>
                      <span className="block text-xs text-ink-3">{tool.description}</span>
                    </td>
                    <td className="w-40">
                      <select aria-label={`State of ${tool.name}`} value={toolState(tool.name)} disabled={locked} onChange={(e) => setToolState(tool.name, e.target.value)}>
                        <option value="allowed">Allowed</option>
                        <option value="approval">Needs approval</option>
                        <option value="off">Not granted</option>
                        <option value="prohibited">Prohibited</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Files" subtitle="One glob per line, starting with /project/… or **/…. Protected paths are checked first, on the written and the resolved path. Anything not readable or writable is denied.">
          <div className="space-y-3">
            <ListField label="Protected paths (never accessible)" value={body.protected_paths} disabled={locked} error={problems.protected_paths} onChange={(v) => set("protected_paths", v)} />
            <ListField label="Readable paths" value={body.read_paths} disabled={locked} error={problems.read_paths} onChange={(v) => set("read_paths", v)} />
            <ListField label="Writable paths" value={body.write_paths} disabled={locked} error={problems.write_paths} onChange={(v) => set("write_paths", v)} />
            <ListField label="Paths that need approval" value={body.approval_paths} disabled={locked} error={problems.approval_paths} onChange={(v) => set("approval_paths", v)} />
          </div>
        </Panel>

        <Panel title="Network" subtitle="Simulated. Host matching is exact, and IP addresses are always refused.">
          <div className="space-y-3">
            <label className="flex items-center gap-2 text-[13px]">
              <input type="checkbox" checked={body.network.enabled} disabled={locked} onChange={(e) => set("network", { ...body.network, enabled: e.target.checked })} />
              Network tool enabled
            </label>
            <ListField label="Allowed hosts" hint="For example api.example.com" value={body.network.allowed_hosts} disabled={locked} error={problems.hosts}
              onChange={(v) => set("network", { ...body.network, allowed_hosts: v })} />
            <ListField label="Allowed methods" hint={METHODS.join(", ")} value={body.network.allowed_methods} disabled={locked} error={problems.methods}
              onChange={(v) => set("network", { ...body.network, allowed_methods: v })} />
          </div>
        </Panel>

        <Panel title="Content and limits">
          <div className="space-y-3">
            <ListField label="Prohibited content (regular expressions, one per line)" value={body.prohibited_content} disabled={locked}
              onChange={(v) => set("prohibited_content", v)} />
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <NumberField label="Max steps per run" value={body.limits.max_steps} disabled={locked} error={problems.max_steps} onChange={(n) => set("limits", { ...body.limits, max_steps: n })} />
              <NumberField label="Max calls per tool" value={body.limits.max_calls_per_tool} disabled={locked} error={problems.max_calls_per_tool} onChange={(n) => set("limits", { ...body.limits, max_calls_per_tool: n })} />
              <NumberField label="Max bytes per write" value={body.limits.max_write_bytes} disabled={locked} error={problems.max_write_bytes} onChange={(n) => set("limits", { ...body.limits, max_write_bytes: n })} />
              <NumberField label="Repeats of a denied action before the run ends" value={body.retry.same_action_denials} disabled={locked} error={problems.same_action_denials} onChange={(n) => set("retry", { ...body.retry, same_action_denials: n })} />
              <NumberField label="Total denials before the run ends" value={body.retry.total_denials} disabled={locked} error={problems.total_denials} onChange={(n) => set("retry", { ...body.retry, total_denials: n })} />
            </div>
          </div>
        </Panel>
      </div>

      {!locked && (
        <div className="sticky bottom-0 mt-4 flex flex-wrap items-center gap-3 border-t border-line bg-bg py-3">
          <Button variant="primary" disabled={busy || invalid || !dirty} onClick={() => void save()}>
            {busy ? "Saving…" : isNew ? "Create policy" : "Save as new version"}
          </Button>
          <span className="text-xs text-ink-3">
            {invalid ? "Fix the highlighted fields to save." : isNew ? "" : dirty ? "Unsaved changes. Saving keeps the current version in the history." : "No changes."}
          </span>
          {!isNew && <Button variant="danger" className="ml-auto" disabled={busy} onClick={() => setConfirming(true)}>Deactivate</Button>}
        </div>
      )}
      <ConfirmDialog open={confirming} title={`Deactivate "${row.name}"?`} confirmLabel="Deactivate" busy={busy}
        onConfirm={() => void deactivate()} onCancel={() => setConfirming(false)}>
        New live runs will no longer be able to use it. Its versions stay in the history, and you can restore it from there.
        Runs that already used it keep their records.
      </ConfirmDialog>
    </>
  );
}

export default function PoliciesPage() {
  const [history, setHistory] = useState(false);
  const policies = usePoll<PolicyRow[]>(history ? "/policies?include_inactive=true" : "/policies");
  const tools = usePoll<Tool[]>("/tools");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [cloneFrom, setCloneFrom] = useState<PolicyRow | null>(null);
  const [dirty, setDirty] = useState(false);
  const [pending, setPending] = useState<(() => void) | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [restoreError, setRestoreError] = useState<ApiError | null>(null);
  const [restoring, setRestoring] = useState(false);
  // The row the backend returned from the last save, shown until the refreshed list includes it, so the editor never flickers to another policy.
  const [justSaved, setJustSaved] = useState<PolicyRow | null>(null);
  const rows = useMemo(() => policies.data ?? [], [policies.data]);
  const selected = rows.find((p) => p.id === selectedId) ?? (justSaved && justSaved.id === selectedId ? justSaved : null)
    ?? rows.find((p) => p.active) ?? rows[0] ?? null;

  // Warn before leaving the page with unsaved edits.
  useEffect(() => {
    if (!dirty) return;
    const warn = (e: BeforeUnloadEvent) => { e.preventDefault(); };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);

  /** Run a navigation inside the page, asking first if it would throw away edits. */
  function guarded(action: () => void) {
    if (dirty) setPending(() => action);
    else action();
  }

  async function restore(row: PolicyRow) {
    setRestoring(true);
    setRestoreError(null);
    try {
      const saved = await api<PolicyRow>(`/policies/${row.id}/restore`, { method: "POST" });
      setNotice(`Restored version ${row.version} of "${row.name}" as version ${saved.version}.`);
      setJustSaved(saved);
      setSelectedId(saved.id);
      policies.refresh();
    } catch (err) {
      setRestoreError(err as ApiError);
    } finally {
      setRestoring(false);
    }
  }

  if (policies.loading && !policies.data) return <Loading />;

  const active = cloneFrom ?? selected;
  const groups = new Map<string, PolicyRow[]>();
  for (const row of rows) groups.set(row.id.startsWith("benchmark:") ? row.id : row.name, [...(groups.get(row.id.startsWith("benchmark:") ? row.id : row.name) ?? []), row]);

  return (
    <>
      <PageHeader title="Policy management" description="The deterministic rules checked before anything else. The contextual assessor can only make them stricter, never looser." />
      <ErrorNotice error={policies.error ?? tools.error ?? restoreError} />
      <SuccessNotice message={notice} onDismiss={() => setNotice(null)} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[15rem_1fr]">
        <Panel title="Policies" actions={
          <label className="flex items-center gap-1.5 text-xs text-ink-2">
            <input type="checkbox" checked={history} onChange={(e) => guarded(() => { setHistory(e.target.checked); })} />History
          </label>
        }>
          {rows.length === 0 ? <EmptyState title="No policies" /> : (
            <ul className="space-y-1">
              {[...groups.values()].map((versions) => versions.map((p, index) => (
                <li key={p.id} className={index > 0 ? "pl-3" : ""}>
                  <button type="button" aria-current={!cloneFrom && active?.id === p.id}
                    onClick={() => guarded(() => { setCloneFrom(null); setSelectedId(p.id); setNotice(null); })}
                    className={`w-full rounded px-2 py-1.5 text-left text-[13px] ${!cloneFrom && active?.id === p.id ? "bg-raised font-medium" : "hover:bg-raised"}`}>
                    <span className={`block truncate ${p.active ? "" : "text-ink-3"}`}>{index === 0 ? p.name : `v${p.version}`}</span>
                    <span className="text-xs text-ink-3">
                      {index === 0 && `v${p.version}`}{p.read_only ? " · benchmark" : ""}{!p.active ? (index === 0 ? " · deactivated" : " · earlier version") : ""}
                    </span>
                  </button>
                </li>
              )))}
            </ul>
          )}
          <p className="mt-3 border-t border-line pt-3 text-xs text-ink-3">To make your own, open a policy and choose <b>Create a copy</b>.</p>
        </Panel>
        <div className="min-w-0">
          {!active ? <EmptyState title="No policy selected" /> : (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-3">
                <h2 className="font-semibold">{cloneFrom ? `New policy from ${cloneFrom.name}` : `${active.name} · v${active.version}`}</h2>
                {!cloneFrom && active.read_only && <Status tone="neutral" glyph="■">Read-only: benchmark results depend on it</Status>}
                {!cloneFrom && !active.read_only && !active.active && <Status tone="neutral" glyph="■">Not active · saved {shortTime(active.created_at)}</Status>}
                {!cloneFrom && !active.read_only && active.active && <Status tone="good" glyph="●">Active</Status>}
                {!cloneFrom && <code className="font-mono text-[11px] text-ink-3" title={active.hash}>hash {active.hash.slice(0, 12)}</code>}
                <div className="ml-auto flex gap-2">
                  {!cloneFrom && !active.read_only && !active.active && (
                    <Button variant="primary" disabled={restoring} onClick={() => void restore(active)}>{restoring ? "Restoring…" : "Restore this version"}</Button>
                  )}
                  {!cloneFrom && <Button onClick={() => guarded(() => { setCloneFrom(active); setNotice(null); })}>Create a copy</Button>}
                  {cloneFrom && <Button onClick={() => { setCloneFrom(null); setDirty(false); }}>Discard copy</Button>}
                </div>
              </div>
              <PolicyEditor
                key={`${cloneFrom ? "clone" : "edit"}-${active.id}`}
                row={active}
                tools={tools.data ?? []}
                isNew={cloneFrom !== null}
                onDirtyChange={setDirty}
                onSaved={({ row, message }) => { setDirty(false); setCloneFrom(null); setJustSaved(row); setSelectedId(row.id); setNotice(message); policies.refresh(); }}
                onDeactivated={(name) => { setDirty(false); setCloneFrom(null); setSelectedId(null); setNotice(`Deactivated "${name}". Turn on History to restore it.`); policies.refresh(); }}
              />
            </>
          )}
        </div>
      </div>
      <ConfirmDialog open={pending !== null} title="Discard unsaved changes?" confirmLabel="Discard changes"
        onConfirm={() => { const next = pending; setPending(null); setDirty(false); next?.(); }} onCancel={() => setPending(null)}>
        Your edits to this policy have not been saved.
      </ConfirmDialog>
    </>
  );
}
