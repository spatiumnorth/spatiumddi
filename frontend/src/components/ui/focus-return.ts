/**
 * Where keyboard focus goes when the control a dialog (or menu) would give it
 * back to cannot take it: it is not focusable (a table row), already gone
 * (a delete whose refetch ran first, #3909), or about to go (a row removed
 * right after the confirm closes). Never the page body (#3908, #3909).
 *
 * One helper for both callers: the shared dialog hook (`useFocusTrap`) and
 * the right-click menu (`context-menu.tsx`).
 */

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** A lazily-resolved fallback: evaluated when focus is actually lost, since
 *  the rows around a removed one are re-rendered by then. */
export type FocusSuccessor = () => HTMLElement | null;

function focusables(root: Element): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE));
}

/** `el` can take focus now: in the page, not the body. */
function usable(el: HTMLElement | null | undefined): el is HTMLElement {
  return !!el && el !== document.body && el.isConnected;
}

function focusProgrammatic(el: HTMLElement) {
  if (!el.hasAttribute("tabindex") && !el.matches(FOCUSABLE)) {
    el.setAttribute("tabindex", "-1");
  }
  el.focus();
}

/** Fallbacks for the control `from`, resolved at use time: the same control
 *  in the next row, then in the previous row, then the list or table, then
 *  the page's heading. Rows are `tr`, `[role=row]` or `li`. */
export function captureSuccessors(
  from: Element | null | undefined,
): FocusSuccessor[] {
  const out: FocusSuccessor[] = [];
  if (from) {
    const row = from.closest<HTMLElement>('tr, [role="row"], li');
    if (row) {
      const idx = focusables(row).indexOf(from as HTMLElement);
      const pick = (r: Element | null) => () => {
        if (!r || !r.isConnected) return null;
        const items = focusables(r);
        return items[Math.max(idx, 0)] ?? items[0] ?? null;
      };
      out.push(pick(row.nextElementSibling), pick(row.previousElementSibling));
      const list = row.closest<HTMLElement>(
        'table, [role="table"], [role="grid"], ul, ol',
      );
      if (list) out.push(() => (list.isConnected ? list : null));
    }
  }
  out.push(() =>
    document.querySelector<HTMLElement>(
      'main h1, main h2, h1, h2, main, [role="main"]',
    ),
  );
  return out;
}

function focusSuccessor(successors: FocusSuccessor[]) {
  for (const s of successors) {
    const el = s();
    if (usable(el)) {
      focusProgrammatic(el);
      return;
    }
  }
}

const WATCH_MS = 5000;

/**
 * Focus the first of `targets` that is still in the page. When none is (and
 * focus has not already been placed elsewhere in the page), or
 * the one chosen leaves the page within a few seconds (the list refetch that
 * removes the deleted row's own button), and focus has then fallen to the
 * body, move it to the first usable successor instead.
 */
export function returnFocus(
  targets: (HTMLElement | null | undefined)[],
  successors: FocusSuccessor[],
): void {
  const target = targets.find(usable);
  if (target) focusProgrammatic(target);
  if (target && document.activeElement === target) {
    // Only a control in a list row can be removed by a refetch; anything
    // else keeps no watcher.
    if (
      typeof MutationObserver === "undefined" ||
      !target.closest('tr, [role="row"], li')
    ) {
      return;
    }
    const obs = new MutationObserver(() => {
      if (target.isConnected) return;
      obs.disconnect();
      clearTimeout(timer);
      const a = document.activeElement;
      if (!a || a === document.body) focusSuccessor(successors);
    });
    const timer = setTimeout(() => obs.disconnect(), WATCH_MS);
    obs.observe(document.body, { childList: true, subtree: true });
    return;
  }
  if (!target) {
    // The dialog's owner already placed focus (a panel's trigger, handed
    // focus as the confirm closes, #3484): a successor must not take it
    // back. Only a focus that fell to the body is lost (#4111).
    const a = document.activeElement;
    if (a instanceof HTMLElement && usable(a)) return;
    focusSuccessor(successors);
  }
}
