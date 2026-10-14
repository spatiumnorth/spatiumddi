import { cn } from "@/lib/utils";

/** Pill-style on/off switch — primary brand colour when on, muted
 * when off. Used in Settings forms and on the Features page so the
 * two surfaces feel consistent. The state change fires via
 * ``onChange`` (mirroring the native ``<input>`` API) so callers can
 * either await an async mutation or commit to local form state. */
export function Toggle({
  checked,
  onChange,
  disabled,
  label,
  title,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  /** Accessible label for screen readers when no surrounding text
   *  describes what the toggle controls (e.g. an icon-only row). */
  label?: string;
  /** Tooltip; carries the reason while ``disabled`` (#1341). */
  title?: string;
}) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-label={label}
      title={title}
      onClick={() => !disabled && onChange(!checked)}
      disabled={disabled}
      className={cn(
        "relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus:outline-none disabled:cursor-not-allowed disabled:opacity-60",
        checked ? "bg-primary" : "bg-muted-foreground/30",
      )}
    >
      <span
        className={cn(
          "pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform",
          checked ? "translate-x-4" : "translate-x-0",
        )}
      />
    </button>
  );
}
