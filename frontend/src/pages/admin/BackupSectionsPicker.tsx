import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Layers, Loader2 } from "lucide-react";

import { ListReadError } from "@/components/ui/list-read-error";
import { backupApi, type BackupSection } from "@/lib/api";

/**
 * Shared section-checklist for both restore flows (issue #117
 * Phase 2b). Reads the catalog from ``GET /backup/sections`` and
 * renders one row per section with a checkbox + description +
 * ``volatile`` / ``always-on`` flag.
 *
 * Usage pattern:
 *
 * ```tsx
 * const [mode, setMode] = useState<"full" | "selective">("full");
 * const [sections, setSections] = useState<string[]>([]);
 * <BackupSectionsPicker
 *   mode={mode}
 *   onModeChange={setMode}
 *   selected={sections}
 *   onChange={setSections}
 * />
 * ```
 *
 * Selecting "full" hides the checklist (and clears the selection).
 * Selecting "selective" reveals the checklist; the operator picks
 * which sections to apply. ``platform_internal`` is rendered as
 * forced-on (the schema head + OUI cache always ride along) and
 * ``volatile`` sections are unticked by default but operators can
 * still tick them.
 */
export function BackupSectionsPicker({
  mode,
  onModeChange,
  selected,
  onChange,
  selectiveDisabledReason,
}: {
  mode: "full" | "selective";
  onModeChange: (m: "full" | "selective") => void;
  selected: string[];
  onChange: (next: string[]) => void;
  /** When set, the Selective option is disabled and this says why
   *  (#2222) — e.g. the archive's dump format is not known yet. */
  selectiveDisabledReason?: string | null;
}) {
  const sectionsQ = useQuery({
    queryKey: ["backup-sections"],
    queryFn: backupApi.listSections,
    staleTime: 5 * 60 * 1000,
  });

  // Auto-tick all non-volatile selectable sections the first time
  // the operator flips into selective mode + the catalog has
  // loaded. Operators can untick individually after that.
  useEffect(() => {
    if (mode !== "selective") return;
    if (!sectionsQ.data || selected.length > 0) return;
    const defaults = sectionsQ.data
      .filter((s) => s.selectable && !s.volatile)
      .map((s) => s.key);
    onChange(defaults);
  }, [mode, sectionsQ.data, selected.length, onChange]);

  function toggle(key: string) {
    if (selected.includes(key)) {
      onChange(selected.filter((k) => k !== key));
    } else {
      onChange([...selected, key]);
    }
  }

  return (
    <div className="rounded-md border bg-muted/20 p-3">
      <div className="mb-2 flex items-center gap-2 text-xs">
        <Layers className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="font-medium">Restore mode</span>
      </div>
      <div className="mb-3 space-y-1">
        <label className="flex items-start gap-2 text-xs">
          <input
            type="radio"
            checked={mode === "full"}
            onChange={() => {
              onModeChange("full");
              onChange([]);
            }}
            className="mt-0.5"
          />
          <span>
            <strong>Full restore</strong> — overwrite every table on this
            install with the archive&rsquo;s contents.
          </span>
        </label>
        <label
          className="flex items-start gap-2 text-xs"
          title={selectiveDisabledReason ?? undefined}
        >
          <input
            type="radio"
            checked={mode === "selective"}
            disabled={!!selectiveDisabledReason}
            onChange={() => onModeChange("selective")}
            className="mt-0.5"
          />
          <span className={selectiveDisabledReason ? "opacity-60" : undefined}>
            <strong>Selective restore</strong> — pick which sections to replace;
            the rest stay untouched.
            {selectiveDisabledReason && (
              <span className="mt-0.5 block text-[11px]">
                {selectiveDisabledReason}
              </span>
            )}
          </span>
        </label>
      </div>

      {mode === "selective" && (
        <>
          <div className="mb-2 flex items-start gap-2 rounded border border-amber-500/30 bg-amber-500/5 px-2 py-1.5 text-[11px] text-amber-700 dark:text-amber-300">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
            <div>
              Selective restore <strong>TRUNCATEs CASCADE</strong> the selected
              sections. Rows in <em>other</em> sections that reference the wiped
              data via foreign key are also removed. Use this for clean-slate
              restores of one section, not for merging.
            </div>
          </div>
          {sectionsQ.isLoading ? (
            <div className="text-xs text-muted-foreground">
              <Loader2 className="mr-1 inline h-3 w-3 animate-spin" />
              Loading catalog…
            </div>
          ) : sectionsQ.isError ? (
            <div className="text-xs">
              <ListReadError
                error={sectionsQ.error}
                what="the backup section catalog"
              />
            </div>
          ) : (
            <ul className="space-y-1">
              {(sectionsQ.data ?? []).map((s: BackupSection) => (
                <li
                  key={s.key}
                  className={`rounded border px-2 py-1.5 text-xs ${
                    !s.selectable
                      ? "border-dashed bg-muted/30"
                      : "bg-background"
                  }`}
                >
                  <label className="flex items-start gap-2">
                    <input
                      type="checkbox"
                      checked={!s.selectable || selected.includes(s.key)}
                      disabled={!s.selectable}
                      onChange={() => toggle(s.key)}
                      className="mt-0.5"
                    />
                    <span className="flex-1">
                      <span className="flex items-center gap-2">
                        <strong>{s.label}</strong>
                        <span className="text-[10px] text-muted-foreground">
                          {s.table_count} tables
                        </span>
                        {s.volatile && (
                          <span className="rounded bg-zinc-500/15 px-1.5 py-0.5 text-[10px] text-zinc-600 dark:text-zinc-400">
                            volatile
                          </span>
                        )}
                        {!s.selectable && (
                          <span className="rounded bg-sky-500/15 px-1.5 py-0.5 text-[10px] text-sky-700 dark:text-sky-400">
                            always
                          </span>
                        )}
                      </span>
                      <span className="mt-0.5 block text-[11px] text-muted-foreground">
                        {s.description}
                      </span>
                    </span>
                  </label>
                </li>
              ))}
            </ul>
          )}
          <div className="mt-2 text-[11px] text-muted-foreground">
            {selected.length === 0 ? (
              <span className="text-amber-700 dark:text-amber-300">
                Tick at least one section to enable Apply.
              </span>
            ) : (
              <>
                Selected: <strong>{selected.length}</strong> section
                {selected.length === 1 ? "" : "s"} (plus
                <code className="mx-1 rounded bg-muted px-1 py-0.5">
                  platform_internal
                </code>
                always restored).
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}
