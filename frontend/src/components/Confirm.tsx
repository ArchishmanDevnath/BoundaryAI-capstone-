"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { Button } from "@/components/ui";

/**
 * A modal confirmation built on the native <dialog>: it traps focus, closes on Escape (which counts as cancelling),
 * and starts with focus on the safe choice so pressing Enter does not confirm by accident.
 */
export function ConfirmDialog({ open, title, children, confirmLabel, busy = false, onConfirm, onCancel }: {
  open: boolean; title: string; children?: ReactNode; confirmLabel: string; busy?: boolean; onConfirm: () => void; onCancel: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      dialog.showModal();
      cancelRef.current?.focus();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  return (
    <dialog
      ref={ref}
      aria-labelledby="confirm-title"
      onCancel={(e) => { e.preventDefault(); if (!busy) onCancel(); }}
      className="w-[min(28rem,calc(100vw-2rem))] rounded-md border border-line-strong bg-panel p-0 text-ink backdrop:bg-black/40"
    >
      <div className="p-5">
        <h2 id="confirm-title" className="text-[15px] font-semibold">{title}</h2>
        {children && <div className="mt-2 text-[13px] text-ink-2">{children}</div>}
        <div className="mt-5 flex justify-end gap-2">
          <Button ref={cancelRef} disabled={busy} onClick={onCancel}>Cancel</Button>
          <Button variant="danger" disabled={busy} onClick={onConfirm}>{busy ? "Working…" : confirmLabel}</Button>
        </div>
      </div>
    </dialog>
  );
}
