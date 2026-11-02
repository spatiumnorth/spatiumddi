import { useCallback, useId, useRef, useState } from "react";
import { cn } from "@/lib/utils";
import { useDismissableMenu } from "@/hooks/useDismissableMenu";

export type FilterMode = "contains" | "begins" | "ends" | "regex";

const MODES: readonly { mode: FilterMode; glyph: string; label: string }[] = [
  { mode: "contains", glyph: "⊂", label: "Contains" },
  { mode: "begins", glyph: "^", label: "Begins" },
  { mode: "ends", glyph: "$", label: "Ends" },
  { mode: "regex", glyph: ".*", label: "Regex" },
];

/**
 * The match-mode button on a column filter (Contains / Begins / Ends /
 * Regex), shared by the IPAM address table and the DNS records table,
 * which carried identical copies with no Esc and no outside close
 * (#3159). Closes under the shared popover contract
 * (`useDismissableMenu`) and is named for what it does, not for the
 * glyph on its face.
 */
export function FilterModePicker({
  value,
  onChange,
}: {
  value: FilterMode;
  onChange: (mode: FilterMode) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const panelId = useId();
  const close = useCallback(() => setOpen(false), []);
  const { onBlur } = useDismissableMenu({
    open,
    onClose: close,
    containerRef: ref,
    triggerRef,
  });
  const current = MODES.find((m) => m.mode === value) ?? MODES[0]!;

  return (
    <div ref={ref} className="relative" onBlur={onBlur}>
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-label={`Filter mode: ${current.label}`}
        aria-haspopup="true"
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        className="rounded-r border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground hover:bg-accent"
        title="Filter mode"
      >
        {current.glyph}
      </button>
      {open && (
        <div
          id={panelId}
          className="absolute left-0 top-full z-30 mt-0.5 w-32 rounded-md border bg-popover shadow-md"
        >
          {MODES.map((m) => (
            <button
              key={m.mode}
              type="button"
              aria-pressed={value === m.mode}
              onClick={() => {
                onChange(m.mode);
                setOpen(false);
                triggerRef.current?.focus();
              }}
              className={cn(
                "w-full px-3 py-1.5 text-left text-xs hover:bg-accent",
                value === m.mode && "font-semibold text-primary",
              )}
            >
              {m.glyph} {m.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
