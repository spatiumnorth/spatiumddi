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

const ROW = 'tr, [role="row"], li, [role="treeitem"]';

/** The repeated unit `from` sits in: a row, a tree item, or (#4221) a card,
 *  a `div` whose next or previous sibling has the same tag and classes. */
function repeatedUnit(from: Element): HTMLElement | null {
  const row = from.closest<HTMLElement>(ROW);
  if (row) return row;
  let a: HTMLElement | null = from.parentElement;
  for (let i = 0; a && i < 6; i++, a = a.parentElement) {
    if (a.matches('main, body, [role="dialog"]')) return null;
    const twin = (s: Element | null) =>
      !!s && s.tagName === a!.tagName && s.className === a!.className;
    if (twin(a.nextElementSibling) || twin(a.previousElementSibling)) return a;
  }
  return null;
}

/** Fallbacks for the control `from`, resolved at use time: the same control
 *  in the next row, then in the previous row, then the list, table or tree,
 *  then the page's heading. A unit is a `tr`, `[role=row]`, `li`, tree item
 *  or card. */
export function captureSuccessors(
  from: Element | null | undefined,
): FocusSuccessor[] {
  const out: FocusSuccessor[] = [];
  if (from) {
    const row = repeatedUnit(from);
    if (row) {
      // `from` is the unit itself (a tree item that takes focus): the
      // neighbour unit is the target, not a control inside it.
      const idx =
        from === row ? -1 : focusables(row).indexOf(from as HTMLElement);
      const pick = (r: Element | null) => () => {
        if (!r || !r.isConnected) return null;
        if (from === row) return r as HTMLElement;
        const items = focusables(r);
        return items[Math.max(idx, 0)] ?? items[0] ?? null;
      };
      out.push(pick(row.nextElementSibling), pick(row.previousElementSibling));
      const list = row.parentElement?.closest<HTMLElement>(
        'table, [role="table"], [role="grid"], [role="tree"], ul, ol',
      );
      const container = list ?? row.parentElement;
      if (container) out.push(() => (container.isConnected ? container : null));
    } else {
      // No unit: the only card has no sibling to match (#4224). Remember the
      // control's ancestors; once the card is gone, the nearest one still in
      // the page is the list that held it.
      const chain: HTMLElement[] = [];
      let a = from.parentElement;
      for (let i = 0; a && i < 8; i++, a = a.parentElement) {
        if (a.matches('main, body, [role="dialog"]')) break;
        chain.push(a);
      }
      if (chain.length)
        out.push(() => chain.find((c) => c.isConnected) ?? null);
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
    // Any control can be removed by a refetch (a table row's button, a tree
    // item, a card's Delete, #4221). The watcher acts only if the target
    // leaves the page and focus falls to the body.
    if (typeof MutationObserver === "undefined") return;
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

/**
 * Call from a row's own control that deletes (or acknowledges, snoozes, ...)
 * with no confirm dialog, just before the mutation starts (#4864). The
 * control goes when the list is read again without it, and with it keyboard
 * focus; this arms the same watcher a dialog close does, so focus lands on
 * the next row's same control, the previous one's, the list, then the
 * heading, never the page body. A pointer press that left focus on the body
 * arms nothing.
 */
export function armRemovalFocus(): void {
  const from = document.activeElement;
  if (!(from instanceof HTMLElement) || from === document.body) return;
  returnFocus([from], captureSuccessors(from));
}
