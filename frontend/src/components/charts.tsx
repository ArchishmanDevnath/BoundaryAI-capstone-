"use client";

import { useState, type ReactNode } from "react";
import { CONFIG_COLORS, CONFIG_NAMES, pct } from "./ui";

/** Hover and keyboard-focus tooltip. The hit target is the whole row, larger than the thin mark. */
function Tip({ content, children }: { content: ReactNode; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div
      className="relative"
      tabIndex={0}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      {children}
      {open && (
        <div role="tooltip" className="pointer-events-none absolute bottom-full left-1/4 z-20 mb-1 w-max max-w-72 rounded border border-line-strong bg-raised px-2.5 py-1.5 text-xs shadow-lg">
          {content}
        </div>
      )}
    </div>
  );
}

export interface BarDatum {
  key: string;
  label: string;
  value: number | null;
  color: string;
  right: string;
  tip: ReactNode;
}

function Bar({ value, color, max = 1 }: { value: number | null; color: string; max?: number }) {
  const width = value === null ? 0 : Math.max(0, Math.min(1, value / max)) * 100;
  return (
    <div className="h-3 w-full">
      {value !== null && (
        <div className="h-full rounded-r-[4px]" style={{ width: width === 0 ? "2px" : `${width}%`, background: color }} />
      )}
    </div>
  );
}

/** Horizontal bars on one shared 0-100% axis, each row directly labeled. */
export function RateBars({ rows, target, targetLabel }: { rows: BarDatum[]; target?: number; targetLabel?: string }) {
  return (
    <div>
      <div className="relative">
        {rows.map((row) => (
          <Tip key={row.key} content={row.tip}>
            <div className="grid grid-cols-[9.5rem_1fr_6.5rem] items-center gap-2 rounded py-1 hover:bg-raised">
              <span className="truncate text-xs text-ink-2">{row.label}</span>
              <div className="border-l border-line-strong">
                <Bar value={row.value} color={row.color} />
              </div>
              <span className="tnum text-right text-xs">{row.right}</span>
            </div>
          </Tip>
        ))}
        {target !== undefined && (
          <div className="pointer-events-none absolute inset-y-0 left-[10rem] right-[7rem]" aria-hidden>
            <div className="absolute inset-y-0 border-l border-dashed border-ink-3" style={{ left: `${target * 100}%` }} />
          </div>
        )}
      </div>
      {targetLabel && <div className="mt-1 text-right text-xs text-ink-3">Dashed line: proposed target ({targetLabel}), not a result</div>}
    </div>
  );
}

export function ConfigLegend({ configs }: { configs: string[] }) {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-2">
      {configs.map((c) => (
        <span key={c} className="inline-flex items-center gap-1.5">
          <span aria-hidden className="h-2.5 w-2.5 rounded-sm" style={{ background: CONFIG_COLORS[c] }} />
          {CONFIG_NAMES[c] ?? c}
        </span>
      ))}
    </div>
  );
}

export interface GroupRow {
  group: string;
  values: { config: string; value: number | null; numerator: number | null; denominator: number | null }[];
}

/** One group per row, with a bar per configuration. Colors follow the configuration, never its rank. */
export function GroupedRateBars({ rows }: { rows: GroupRow[] }) {
  return (
    <div className="space-y-3">
      {rows.map((row) => (
        <div key={row.group}>
          <div className="mb-1 text-xs font-medium">{row.group}</div>
          <div className="space-y-0.5">
            {row.values.map((v) => (
              <Tip key={v.config} content={
                <span>
                  <b>{CONFIG_NAMES[v.config]}</b><br />
                  {v.value === null ? "Not applicable or no attempts" : `${pct(v.value)} (${v.numerator} of ${v.denominator})`}
                </span>
              }>
                <div className="grid grid-cols-[1fr_6.5rem] items-center gap-2 rounded hover:bg-raised">
                  <div className="border-l border-line-strong"><Bar value={v.value} color={CONFIG_COLORS[v.config]} /></div>
                  <span className="tnum text-right text-xs text-ink-2">{v.value === null ? "n/a" : `${pct(v.value, 0)} ${v.numerator}/${v.denominator}`}</span>
                </div>
              </Tip>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

/** Part-to-whole as one segmented bar, with 2px gaps and a legend carrying the counts. */
export function SegmentedBar({ segments }: { segments: { label: string; value: number; color: string; glyph: string }[] }) {
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  if (total === 0) return null;
  return (
    <div>
      <div className="flex h-3 gap-[2px]">
        {segments.filter((s) => s.value > 0).map((s) => (
          <div key={s.label} title={`${s.label}: ${s.value}`} className="first:rounded-l-[4px] last:rounded-r-[4px]" style={{ flexGrow: s.value, background: s.color, minWidth: 3 }} />
        ))}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs">
        {segments.map((s) => (
          <span key={s.label} className="tnum inline-flex items-center gap-1.5">
            <span aria-hidden className="font-bold" style={{ color: s.color }}>{s.glyph}</span>
            {s.label} <b>{s.value.toLocaleString()}</b> <span className="text-ink-3">{pct(s.value / total, 0)}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
