/**
 * Keyboard shortcuts — the single source of truth (issue #81).
 *
 * Every binding the app responds to is declared here once, and both
 * halves consume this file:
 *
 *   * the **handlers** match against it via {@link matchesShortcut}
 *   * the **help overlay** renders it via {@link formatCombo}
 *
 * That coupling is the point: a help page carrying its own hand-written
 * copy of the bindings goes stale the first time someone retunes a
 * handler.
 *
 * **How far that guarantee currently reaches.** Two shortcuts are
 * genuinely wired — `Cmd/Ctrl+K` (matched in `GlobalSearch`) and `?`
 * (matched in `KeyboardShortcutsOverlay`). Retune either here and both
 * the handler and the overlay follow. Everything else is flagged
 * {@link Shortcut.describedOnly}: real behaviour, but implemented in a
 * component that doesn't consult this map — the modal Escape in
 * `use-draggable-modal`, the arrow keys in `GlobalSearch`,
 * Enter/Shift+Enter in the Copilot composer, Backspace in
 * `TagFilterChips` — plus a few that are native browser behaviour.
 * Those rows are listed because from the operator's side they're
 * indistinguishable from the ones we own, but they are exactly the ones
 * that can drift.
 *
 * Adding a binding? Declare it here and have the handler match on it
 * via {@link matchesShortcut}, rather than adding another
 * described-only row. Adding it straight to a component means it never
 * shows up in the overlay at all.
 */

/** A single chord. `key` is matched against `KeyboardEvent.key`. */
export interface KeyCombo {
  /** `KeyboardEvent.key` value, compared case-insensitively. */
  key: string;
  /**
   * The primary modifier. **Rendered** per-platform (⌘ on a Mac, Ctrl
   * elsewhere) but **matched** against either — see
   * {@link matchesCombo} for why it is deliberately lenient.
   */
  mod?: boolean;
  shift?: boolean;
  alt?: boolean;
  /** Render override — for keys whose `key` value reads badly ("ArrowUp"). */
  label?: string;
}

export interface Shortcut {
  id: string;
  combos: KeyCombo[];
  description: string;
  /**
   * True when this entry only *describes* a binding whose handler lives
   * elsewhere and does not consult this map — either component-local
   * (the modal Escape in `use-draggable-modal`, the arrow keys in
   * `GlobalSearch`, Enter/Shift+Enter in the Copilot composer) or
   * native browser behaviour.
   *
   * These are the entries that **can** go stale, because nothing links
   * them to the code that implements them. Prefer wiring a new binding
   * (leave this unset and match via {@link matchesShortcut}) over
   * adding another described-only row.
   */
  describedOnly?: boolean;
  /**
   * The grant the binding's handler requires: met when the user holds
   * `action` on ANY of `resourceTypes`. The overlay hides the row from a
   * user who doesn't, because the handler stands down for them and a
   * keycap that does nothing reads as a broken shortcut (#3103). Keep it
   * identical to the check the handler makes.
   */
  requires?: { action: string; resourceTypes: string[] };
}

export interface ShortcutGroup {
  /** Stable key — filter on this, never on the display title. */
  id: string;
  /** Section heading in the overlay. */
  title: string;
  /** When the group only applies in a particular context, say so. */
  context?: string;
  /**
   * Feature module this group's surface belongs to. When set, the
   * overlay hides the group unless that module is enabled — no point
   * advertising bindings for a drawer the operator can't open.
   */
  module?: string;
  shortcuts: Shortcut[];
}

/**
 * True on macOS-like platforms, where the "mod" key renders as ⌘ and is
 * reported as `metaKey`. Everywhere else it is Ctrl.
 *
 * `navigator.platform` is deprecated but is still the most broadly
 * supported signal; `userAgentData` is Chromium-only, so it is tried
 * first and this is the fallback. Guarded for non-browser contexts
 * (tests, SSR) rather than assuming `navigator` exists.
 */
export function isMacPlatform(): boolean {
  if (typeof navigator === "undefined") return false;
  const uaPlatform = (
    navigator as Navigator & { userAgentData?: { platform?: string } }
  ).userAgentData?.platform;
  const platform = uaPlatform || navigator.platform || "";
  return /mac|iphone|ipad|ipod/i.test(platform);
}

/** Render one combo for display, e.g. `⌘K` / `Ctrl+K` / `Shift+Enter`. */
export function formatCombo(combo: KeyCombo, mac = isMacPlatform()): string {
  const parts: string[] = [];
  if (combo.mod) parts.push(mac ? "⌘" : "Ctrl");
  if (combo.alt) parts.push(mac ? "⌥" : "Alt");
  if (combo.shift) parts.push(mac ? "⇧" : "Shift");
  // Letter keys are stored lowercase because that's what we match
  // against `KeyboardEvent.key`; a keycap reads as "⌘K", not "⌘k".
  // Only single characters are touched — "Enter" / "Escape" keep their
  // capitalisation, and an explicit `label` is used verbatim.
  const key =
    combo.label ??
    (combo.key.length === 1 ? combo.key.toUpperCase() : combo.key);
  parts.push(key);
  // ⌘ and friends read as one glyph beside the key; the spelled-out
  // modifiers need a separator or "CtrlK" runs together.
  return mac ? parts.join("") : parts.join("+");
}

/**
 * Does this keyboard event match the combo?
 *
 * Modifier matching is strict in both directions — a combo that doesn't
 * ask for Alt will not match an event with Alt held — so Ctrl+K and
 * Ctrl+Alt+K can't both fire the same handler.
 *
 * `mod` is the one deliberate exception: it accepts **either** Cmd or
 * Ctrl regardless of platform. It renders per-platform (⌘K on a Mac,
 * Ctrl+K elsewhere) but matches both, which is exactly what the
 * pre-#81 `(e.metaKey || e.ctrlKey)` check in `GlobalSearch` did.
 * Tightening that to the platform's own modifier would quietly stop
 * Ctrl+K working for Mac users who have it in their fingers, and
 * retuning existing bindings isn't this change's job.
 */
export function matchesCombo(e: KeyboardEvent, combo: KeyCombo): boolean {
  if (e.key.toLowerCase() !== combo.key.toLowerCase()) return false;
  const mod = e.metaKey || e.ctrlKey;
  if (mod !== !!combo.mod) return false;
  if (e.altKey !== !!combo.alt) return false;
  // Shift is only compared when the combo cares. Typing "?" needs Shift
  // on a US layout but not on every layout, so a shortcut keyed on the
  // resulting *character* must not also demand the modifier that
  // happened to produce it.
  if (combo.shift !== undefined && e.shiftKey !== combo.shift) return false;
  return true;
}

/** Any-of-the-combos convenience wrapper around {@link matchesCombo}. */
export function matchesShortcut(e: KeyboardEvent, shortcut: Shortcut): boolean {
  return shortcut.combos.some((c) => matchesCombo(e, c));
}

/**
 * Is the user typing into something?
 *
 * Printable-character shortcuts (`?`) must stand down inside form
 * fields, or the operator can't type a question mark into a
 * description. Checked against the *event target* rather than
 * `document.activeElement` so it stays correct inside shadow roots and
 * portalled dialogs.
 */
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  // Custom widgets that opt into text entry (combobox / searchbox roles).
  const role = target.getAttribute("role");
  return role === "textbox" || role === "combobox" || role === "searchbox";
}

// ── The bindings ────────────────────────────────────────────────────────

/** Open the global search palette. Matched in `GlobalSearch.tsx`. */
export const OPEN_GLOBAL_SEARCH: Shortcut = {
  id: "global-search",
  // `shift: false` is load-bearing. The pre-#81 check was
  // `e.key === "k"` — case-*sensitive*, so Shift never matched because
  // it yields `"K"`. `matchesCombo` compares case-insensitively, so
  // without this the palette would start toggling on Ctrl+Shift+K,
  // which is the Web Console shortcut in both Firefox and Chrome.
  combos: [{ key: "k", mod: true, shift: false }],
  description: "Open global search",
};

/** Open this help overlay. Matched in `KeyboardShortcutsOverlay.tsx`. */
export const SHOW_SHORTCUTS: Shortcut = {
  id: "show-shortcuts",
  // No `shift` constraint: "?" is Shift+/ on US layouts but a bare key
  // elsewhere, and demanding Shift would break those keyboards.
  combos: [{ key: "?" }],
  description: "Show keyboard shortcuts",
};

/**
 * Add a record to the open DNS zone. Matched in `DNSPage.tsx` (#996).
 *
 * `+ Add Record` became the only always-visible primary on the zone
 * detail when the eleven-button header folded into two menus, so it
 * earns a binding — and a WIRED one rather than a `describedOnly` row,
 * per the note at the top of this file.
 *
 * `mod` is deliberately absent: ⌘N / Ctrl+N is "new window" in every
 * browser and cannot be intercepted reliably, and ⌘⇧N is "new private
 * window". A bare letter is safe because `isTypingTarget` stands the
 * handler down inside form fields — the same guard `?` relies on.
 */
export const ADD_DNS_RECORD: Shortcut = {
  id: "dns-add-record",
  combos: [{ key: "n" }],
  description: "Add a record to the open zone",
  // The handler's `canWriteRecords` in DNSPage.tsx (#2529).
  requires: {
    action: "write",
    resourceTypes: ["dns_group", "dns_zone", "dns_record"],
  },
};

export const SHORTCUT_GROUPS: ShortcutGroup[] = [
  {
    id: "global",
    title: "Global",
    shortcuts: [
      OPEN_GLOBAL_SEARCH,
      SHOW_SHORTCUTS,
      {
        id: "escape",
        combos: [{ key: "Escape", label: "Esc" }],
        description: "Close the open dialog, drawer, or palette",
        describedOnly: true,
      },
    ],
  },
  {
    id: "global-search",
    title: "Global search",
    context: "while the search palette is open",
    shortcuts: [
      {
        id: "search-move",
        combos: [
          { key: "ArrowUp", label: "↑" },
          { key: "ArrowDown", label: "↓" },
        ],
        description: "Move between results",
        describedOnly: true,
      },
      {
        id: "search-open",
        combos: [{ key: "Enter" }],
        description: "Open the highlighted result",
        describedOnly: true,
      },
    ],
  },
  {
    id: "copilot",
    title: "Operator Copilot",
    module: "ai.copilot",
    context: "while the chat drawer is open",
    shortcuts: [
      {
        id: "copilot-send",
        combos: [{ key: "Enter", shift: false }],
        description: "Send the message",
        describedOnly: true,
      },
      {
        id: "copilot-newline",
        combos: [{ key: "Enter", shift: true }],
        description: "Insert a newline instead of sending",
        describedOnly: true,
      },
      {
        id: "copilot-history",
        combos: [
          { key: "ArrowUp", label: "↑" },
          { key: "ArrowDown", label: "↓" },
        ],
        description:
          "Walk back through messages you've sent — only from an empty composer, so a draft is never overwritten",
        describedOnly: true,
      },
    ],
  },
  {
    id: "dns-zone",
    title: "DNS zone",
    context: "while a zone's records are open",
    shortcuts: [ADD_DNS_RECORD],
  },
  {
    id: "tables",
    title: "Tables and lists",
    shortcuts: [
      {
        id: "range-select",
        combos: [{ key: "Click", shift: true }],
        description:
          "Select every row between the last one you clicked and this one",
        describedOnly: true,
      },
    ],
  },
  {
    id: "inline",
    title: "Inline editing and filters",
    shortcuts: [
      {
        id: "inline-apply",
        combos: [{ key: "Enter" }],
        description: "Apply the value in the focused field",
        describedOnly: true,
      },
      {
        id: "inline-cancel",
        combos: [{ key: "Escape", label: "Esc" }],
        description: "Cancel without saving",
        describedOnly: true,
      },
      {
        id: "tag-backspace",
        combos: [{ key: "Backspace" }],
        description: "Remove the last tag from an empty tag filter",
        describedOnly: true,
      },
    ],
  },
];
