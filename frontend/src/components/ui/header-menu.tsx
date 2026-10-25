import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { ChevronDown } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { HeaderButton } from "@/components/ui/header-button";

// Dropdown companion to HeaderButton (#996).
//
// The DNS zone detail had grown to ELEVEN peer buttons in one
// non-wrapping row — at ~1,460px with the sidebar open, `+ Add Record`,
// the primary action, was clipped to a `+` sliver at the right edge. The
// HeaderButton ordering convention was written for five or six buttons
// and does not scale past what a row can hold, so the once-per-zone
// actions fold into menus and the many-times-per-session ones stay
// visible.
//
// Lifted from IPAM's local `SyncMenu` rather than written fresh, so the
// two surfaces stop drifting — that page had its own copy of the
// open-state + outside-mousedown dance, and a third copy was about to
// be written here. Same argument as `lib/shortcuts.ts` (#81) and
// `lib/navigation.ts` (#879): one definition the surfaces read.
//
// Keyboard behaviour is the part a hand-rolled copy always misses:
// Enter/Space opens, Up/Down move, Home/End jump, Esc closes and returns
// focus to the trigger. Disabled items are skipped by the arrows rather
// than focused-and-inert.

export type HeaderMenuItem = {
  /** Stable identity for React's list key. Never rendered. */
  key: string;
  /**
   * Deliberately `string`, not `ReactNode`.
   *
   * The item's text IS its accessible name — it is the button's only
   * content besides a decorative icon. A node label could render as an
   * icon or a badge with no text at all, leaving a menu item a screen
   * reader announces as "button" and nothing else, and the type would
   * not say so. Every call site passes a string today; if one ever
   * genuinely needs markup, add an explicit `ariaLabel` alongside it
   * rather than widening this and hoping.
   */
  label: string;
  icon?: LucideIcon;
  iconClassName?: string;
  onSelect: () => void;
  disabled?: boolean;
  /** Tooltip — carries the *reason* when disabled. */
  title?: string;
  /** Renders in the destructive palette and, by convention, sits last. */
  destructive?: boolean;
  /** Draws a divider ABOVE this item. */
  separatorBefore?: boolean;
  /**
   * Makes this a checkbox item (`menuitemcheckbox`): `onSelect` toggles
   * the option and the menu STAYS OPEN, so the choice can be made before
   * the action it modifies (Export's "Include IP addresses", #2722).
   */
  checked?: boolean;
};

type HeaderMenuProps = {
  label: string;
  icon?: LucideIcon;
  items: HeaderMenuItem[];
  title?: string;
  /**
   * Badge dot on the trigger — for a menu holding an item the operator is
   * being nudged toward (Delegate). Hiding an advisory inside a menu
   * otherwise loses the nudge entirely, which is the one real cost of
   * folding a row into menus.
   */
  badge?: boolean;
  badgeTitle?: string;
  className?: string;
};

export function HeaderMenu({
  label,
  icon: Icon,
  items,
  title,
  badge,
  badgeTitle,
  className,
}: HeaderMenuProps) {
  const [open, setOpen] = useState(false);
  const [flipLeft, setFlipLeft] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuId = useId();

  const close = useCallback((focusTrigger: boolean) => {
    setOpen(false);
    if (focusTrigger) triggerRef.current?.focus();
  }, []);

  useEffect(() => {
    if (!open) return;
    const onDocMouseDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    // Esc closes the menu wherever focus is. A mouse open leaves focus
    // on the trigger (or on <body> in Safari, which does not focus a
    // button on click), and a handler on the panel never sees a key
    // pressed there (#2047). Capture phase on the document so it runs
    // before the modal hook's window listener; stopPropagation only
    // because the menu was open and handled it, so a closed menu never
    // swallows the Esc a parent dialog is waiting for.
    //
    // Two guards. An Esc that ends an IME composition belongs to the
    // input method, not to us. And the Esc is ours only while focus is
    // in the menu (trigger or panel) or nowhere (<body>): if a layer
    // opened over the menu without a pointer press — Cmd+K's palette,
    // the `?` overlay, a modal from a page shortcut — focus is in that
    // layer and so is the Esc. The focusout handler on the container
    // normally closes the menu before that can happen; this is the
    // backstop, so a missed focusout cannot yank focus back behind the
    // layer the operator is in.
    const onDocKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.isComposing) return;
      const active = document.activeElement;
      const inMenu =
        !active ||
        active === document.body ||
        (ref.current?.contains(active) ?? false);
      if (!inMenu) return;
      e.preventDefault();
      e.stopPropagation();
      close(true);
    };
    document.addEventListener("mousedown", onDocMouseDown);
    document.addEventListener("keydown", onDocKeyDown, true);
    return () => {
      document.removeEventListener("mousedown", onDocMouseDown);
      document.removeEventListener("keydown", onDocKeyDown, true);
    };
  }, [open, close]);

  // Flip to the left edge when the panel would overflow the viewport. A
  // header menu near the right edge is the common case, so `right-0` is
  // the default and this only rescues the opposite one.
  useLayoutEffect(() => {
    if (!open || !menuRef.current) return;
    const rect = menuRef.current.getBoundingClientRect();
    setFlipLeft(rect.left < 0);
  }, [open]);

  const enabled = items.filter((it) => !it.disabled);

  // `from` is the index to move FROM, so focusing the first item is
  // `focusItem(1, -1)` — one step forward from "before the list" — not
  // `focusItem(0, -1)`, which lands on the last item via the modulo and
  // reads as "the arrow key does nothing sensible". That is the bug the
  // tests in header-menu.test.tsx caught on the first run.
  const focusItem = (delta: number, from?: number) => {
    const nodes = menuRef.current?.querySelectorAll<HTMLButtonElement>(
      "button:not(:disabled)",
    );
    if (!nodes || nodes.length === 0) return;
    const current =
      from ?? Array.from(nodes).findIndex((n) => n === document.activeElement);
    const next = (current + delta + nodes.length) % nodes.length;
    nodes[next]?.focus();
  };

  const onTriggerKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown" || e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      setOpen(true);
      // Focus lands after the panel mounts.
      window.setTimeout(() => focusItem(1, -1), 0);
    }
  };

  const onMenuKeyDown = (e: React.KeyboardEvent) => {
    // Escape is handled by the document listener above, which also
    // covers focus on the trigger.
    if (e.key === "ArrowDown") {
      e.preventDefault();
      focusItem(1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      focusItem(-1);
    } else if (e.key === "Home") {
      e.preventDefault();
      focusItem(1, -1);
    } else if (e.key === "End") {
      e.preventDefault();
      focusItem(-1, 0);
    } else if (e.key === "Tab") {
      setOpen(false);
    }
  };

  // A menu with nothing in it is not a disabled menu, it is not a menu —
  // a forward zone has no Import / Export / Sync at all, and rendering a
  // trigger that opens an empty panel is worse than the row it replaced.
  if (items.length === 0) return null;

  return (
    <div
      ref={ref}
      className={cn("relative", className)}
      // Focus leaving the menu for somewhere else closes it, so an open
      // menu never sits under whatever took focus (a Tab off a mouse-opened
      // trigger, or a layer that focused itself). A null relatedTarget is
      // focus going nowhere — a click on the page, the window losing focus
      // — which the outside-mousedown handler already decides.
      onBlur={(e) => {
        const next = e.relatedTarget as Node | null;
        if (open && next && !e.currentTarget.contains(next)) setOpen(false);
      }}
    >
      <HeaderButton
        ref={triggerRef}
        icon={Icon}
        title={title}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((v) => !v)}
        onKeyDown={onTriggerKeyDown}
        disabled={enabled.length === 0}
      >
        {label}
        {badge && (
          <span
            title={badgeTitle}
            aria-label={badgeTitle}
            className="ml-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-500"
          />
        )}
        <ChevronDown className="h-3.5 w-3.5" />
      </HeaderButton>
      {open && (
        <div
          id={menuId}
          ref={menuRef}
          role="menu"
          aria-label={label}
          onKeyDown={onMenuKeyDown}
          className={cn(
            "absolute z-20 mt-1 min-w-52 overflow-hidden rounded-md border bg-popover shadow-md",
            flipLeft ? "left-0" : "right-0",
          )}
        >
          {items.map((it) => (
            <div key={it.key}>
              {it.separatorBefore && <div className="border-t" />}
              <button
                type="button"
                role={
                  it.checked === undefined ? "menuitem" : "menuitemcheckbox"
                }
                aria-checked={it.checked}
                title={it.title}
                disabled={it.disabled}
                onClick={() => {
                  if (it.checked === undefined) setOpen(false);
                  it.onSelect();
                }}
                className={cn(
                  "flex w-full items-center gap-2 px-3 py-2 text-left text-sm",
                  "hover:bg-muted focus:bg-muted focus:outline-none",
                  "disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-transparent",
                  it.destructive && "text-destructive",
                )}
              >
                {it.icon && (
                  <it.icon
                    className={cn("h-3.5 w-3.5 shrink-0", it.iconClassName)}
                  />
                )}
                {it.checked !== undefined && (
                  <span
                    aria-hidden="true"
                    className="inline-block w-3 shrink-0 text-center"
                  >
                    {it.checked ? "✓" : ""}
                  </span>
                )}
                <span className="min-w-0">{it.label}</span>
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
