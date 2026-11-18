import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Zebra striping for long-list tables. Apply to `<tbody>` so position-based
 * `:nth-child(even)` counts every rendered row — including mixed row types
 * like pool boundaries interleaved with IP rows — rather than only the
 * ones that carry the utility class. Rows with their own `bg-*` (selected,
 * boundary markers) keep their color because their classes are declared
 * later in the cascade.
 *
 * Uses `foreground/X` rather than `muted/X` so the contrast is visible in
 * both themes — `muted` is near-white in light mode (only ~4% lightness
 * difference from the page) and the striping disappears.
 *
 *   <tbody className={zebraBodyCls}>…</tbody>
 */
export const zebraBodyCls =
  "[&>tr:nth-child(even)]:bg-foreground/[0.05] [&>tr:hover]:bg-foreground/[0.09]";

/** Per-row variant for cases where a `<tbody>` isn't the direct parent
 *  (e.g. the row is wrapped in a ContextMenu component). */
export const zebraRowCls =
  "even:bg-foreground/[0.05] hover:bg-foreground/[0.09] even:hover:bg-foreground/[0.09]";

/**
 * Curated swatch palette shared by DNS zones and IP spaces. The key is
 * the value stored in the DB + API (backend validates against the same
 * set); `cls` is the saturated Tailwind bg for dots / stripes, `tint`
 * is a lower-alpha version suitable for painting a whole row background.
 * Keep in sync with VALID_ZONE_COLORS / VALID_SPACE_COLORS in the
 * backend.
 */
export const SWATCH_COLORS: {
  key: string;
  label: string;
  cls: string;
  tint: string;
}[] = [
  {
    key: "slate",
    label: "Slate",
    cls: "bg-slate-400",
    tint: "bg-slate-400/20",
  },
  { key: "red", label: "Red", cls: "bg-red-500", tint: "bg-red-500/15" },
  {
    key: "amber",
    label: "Amber",
    cls: "bg-amber-500",
    tint: "bg-amber-500/20",
  },
  {
    key: "emerald",
    label: "Emerald",
    cls: "bg-emerald-500",
    tint: "bg-emerald-500/15",
  },
  { key: "cyan", label: "Cyan", cls: "bg-cyan-500", tint: "bg-cyan-500/15" },
  { key: "blue", label: "Blue", cls: "bg-blue-500", tint: "bg-blue-500/15" },
  {
    key: "violet",
    label: "Violet",
    cls: "bg-violet-500",
    tint: "bg-violet-500/15",
  },
  { key: "pink", label: "Pink", cls: "bg-pink-500", tint: "bg-pink-500/15" },
];

export function swatchCls(key: string | null | undefined): string | null {
  if (!key) return null;
  return SWATCH_COLORS.find((c) => c.key === key)?.cls ?? null;
}

export function swatchTintCls(key: string | null | undefined): string | null {
  if (!key) return null;
  return SWATCH_COLORS.find((c) => c.key === key)?.tint ?? null;
}

/** Selected (checkbox-ticked) table row (#4075). The tint sits on the `tr`
 *  itself with `!` so it beats the tbody-level zebra rule
 *  (`[&>tr:nth-child(even)]`, higher specificity than a plain `bg-*`) and
 *  the row's own hover. Even and odd rows take different tokens so the
 *  stripes still read across adjacent selected rows; hover is a third,
 *  stronger shade; the accent bar is an inset shadow on the first cell, so
 *  it never shifts layout. Colours live in `index.css`. */
export function selectedRowClass(selected: boolean): string {
  return selected
    ? "even:!bg-[hsl(var(--row-selected-even))] odd:!bg-[hsl(var(--row-selected-odd))] hover:!bg-[hsl(var(--row-selected-hover))] [&>td:first-child]:shadow-[inset_3px_0_0_hsl(var(--primary))]"
    : "";
}
