import { useEffect, useId, useRef, useState } from "react";

/** CSS for the outer flex-center backdrop. Same across every modal. */
export const MODAL_BACKDROP_CLS =
  "fixed inset-0 z-50 flex items-center justify-center bg-black/20 p-2 sm:p-4";

/**
 * Layer stack. Every open dialog is a layer; only the topmost one owns Esc
 * and the Tab trap (#1947, #1948). Separate stacks for the two concerns keep
 * a shell that only drags (no trap) correct for Esc, and both are pushed in
 * mount order so they always agree.
 */
function createLayerStack() {
  const layers: { token: symbol; seq: number }[] = [];
  return {
    /** Register a layer ranked by `seq`; returns the unregister function. */
    push(seq: number): { token: symbol; remove: () => void } {
      const token = Symbol("modal-layer");
      layers.push({ token, seq });
      return {
        token,
        remove: () => {
          const i = layers.findIndex((l) => l.token === token);
          if (i >= 0) layers.splice(i, 1);
        },
      };
    },
    isTop: (token: symbol) =>
      layers.length > 0 &&
      layers.reduce((a, b) => (b.seq > a.seq ? b : a)).token === token,
    size: () => layers.length,
  };
}

/** Rank of a dialog, taken at first render. Render order is parent before
 *  child and earlier before later, whereas effects run child-first — so a
 *  dialog nested in another's JSX (a ConfirmModal in a form) and mounted in
 *  the same commit would otherwise register beneath its own parent. */
let layerSeq = 0;
function useLayerSeq(): number {
  return useState(() => ++layerSeq)[0];
}

const escStack = createLayerStack();
const trapStack = createLayerStack();

/** True while any dialog (or overlay layer) is open. Non-dialog Esc handlers
 *  (the copilot drawer, popovers) consult it so one Esc does not dismiss them
 *  as well as the dialog over them. */
export function hasOpenModal(): boolean {
  return escStack.size() > 0 || trapStack.size() > 0;
}

/** Make an overlay that is not built on these hooks (the search palette) the
 *  topmost layer while `active`, so the dialogs under it neither take its Esc
 *  nor pull its Tab back into themselves. The overlay handles its own Esc and
 *  must stop it propagating. */
export function useOverlayLayer(active: boolean): void {
  useEffect(() => {
    if (!active) return;
    const seq = ++layerSeq;
    const esc = escStack.push(seq);
    const trap = trapStack.push(seq);
    return () => {
      esc.remove();
      trap.remove();
    };
  }, [active]);
}

/**
 * Drag hook for modal dialogs. Returns a style to apply to the dialog card
 * (``transform: translate(x, y)``) and a set of props to spread on whatever
 * element should act as the drag handle (typically the title bar).
 *
 * Esc is bound here too so any modal using the hook gets close-on-Escape
 * "for free" — the safety net when a user drags the dialog off-screen.
 *
 * Lives in its own file (not ``modal.tsx``) so Vite's fast-refresh plugin
 * doesn't warn about mixed component + utility exports.
 */
export function useDraggableModal(onClose: () => void) {
  const seq = useLayerSeq();
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const dragRef = useRef<{
    startX: number;
    startY: number;
    originX: number;
    originY: number;
  } | null>(null);

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      const d = dragRef.current;
      if (!d) return;
      setOffset({
        x: d.originX + (e.clientX - d.startX),
        y: d.originY + (e.clientY - d.startY),
      });
    };
    const onUp = () => {
      dragRef.current = null;
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, []);

  // Esc closes only the topmost dialog, and the event stops there. Each
  // dialog binds its own listener, so without the stack one keypress closed
  // every dialog in a nested stack. `stopImmediatePropagation` matters:
  // React flushes the close in a microtask between two listeners, which
  // would make the dialog underneath the new top before its listener ran.
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);
  useEffect(() => {
    const { token, remove } = escStack.push(seq);
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || !escStack.isTop(token)) return;
      e.stopImmediatePropagation();
      onCloseRef.current();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      remove();
    };
  }, [seq]);

  const startDrag = (e: React.MouseEvent) => {
    // Don't start dragging when the press landed on an interactive control
    // (close button, form input, etc.) — the hit-test walks up to the
    // nearest <button> or <input>/<select>/<textarea> via ``closest``.
    const target = e.target as HTMLElement;
    if (target.closest("button, input, select, textarea, a")) return;
    dragRef.current = {
      startX: e.clientX,
      startY: e.clientY,
      originX: offset.x,
      originY: offset.y,
    };
    e.preventDefault();
  };

  return {
    dialogStyle: { transform: `translate(${offset.x}px, ${offset.y}px)` },
    dragHandleProps: {
      onMouseDown: startDrag,
      className: "cursor-grab active:cursor-grabbing select-none",
      title: "Drag to move",
    },
  };
}

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Modal accessibility: **initial focus + focus trap + focus return**. Attach
 * the returned ref to the dialog container (the element that also carries
 * ``role="dialog"`` + ``aria-modal="true"``).
 *
 * On open it remembers the previously-focused element and — unless a control
 * inside already grabbed focus via ``autoFocus`` (e.g. ConfirmModal's password
 * field) — moves focus into the dialog. Tab / Shift+Tab cycle within the
 * topmost dialog so keyboard focus can't escape to the page behind. On close focus
 * returns to wherever it was, so the operator's place in the page is kept.
 *
 * Lives next to ``useDraggableModal`` so every modal can opt in with one line.
 */
export function useFocusTrap<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const seq = useLayerSeq();
  // The opener is read during the FIRST RENDER, not in the effect: React
  // applies a child's `autoFocus` at commit, before any effect runs, so by
  // then `document.activeElement` is the dialog's own field and "focus
  // return" would restore to a node that is unmounted with the dialog (#2050).
  // Render is the last point focus is still where the operator left it.
  // That is first render of THIS hook instance: every caller mounts the
  // dialog on open and unmounts it on close, which is also what the trap
  // effect below assumes (it runs once, on mount).
  const openerRef = useRef<FocusReturnTargets | undefined>(undefined);
  if (openerRef.current === undefined) {
    openerRef.current = captureFocusReturnTargets();
  }
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    const returnTargets = openerRef.current;
    const { token, remove } = trapStack.push(seq);
    // A dialog that takes this one's place in the same commit (a loading
    // phase handing over to its confirm) is opened while focus sits on this
    // card; it inherits these targets, or its own close would have nowhere
    // to return to (#2723).
    if (returnTargets) cardReturnTargets.set(node, returnTargets);

    // Focus follows a dialog's content. A step that replaces the focused
    // control (Continue → the next step) removes the node focus was on, and
    // the browser drops focus on <body> while the dialog stays open: nothing
    // in it is focused and a screen reader announces nothing (#2723). Put it
    // back on the card, as on open, when exactly that happened.
    let lastFocused: HTMLElement | null = null;
    const onFocusIn = (e: FocusEvent) => {
      if (e.target instanceof HTMLElement) lastFocused = e.target;
    };
    node.addEventListener("focusin", onFocusIn);
    const observer = new MutationObserver(() => {
      if (!node.isConnected || !trapStack.isTop(token)) return;
      const active = document.activeElement;
      if (active && active !== document.body && node.contains(active)) return;
      if (active && active !== document.body) return;
      if (lastFocused && !lastFocused.isConnected) {
        lastFocused = null;
        node.setAttribute("tabindex", "-1");
        node.focus();
      }
    });
    observer.observe(node, { childList: true, subtree: true });

    const focusables = () =>
      Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
        (el) => isVisible(el, node),
      );

    // Respect an existing autoFocus inside the dialog; otherwise focus the
    // dialog container itself (tabindex -1) so screen readers announce it and
    // the operator tabs into the content. Never a control: the first one can
    // be a confirm's destructive button, which Enter would then fire.
    if (!node.contains(document.activeElement)) {
      node.setAttribute("tabindex", "-1");
      node.focus();
    }

    // Bound on the document, not the dialog: focus can sit outside it (the
    // page behind, after a click on the backdrop) and Tab must still come
    // back in. Only the topmost dialog traps; a nested one is a separate
    // portal, so the parent's trap steps aside while it is open.
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Tab" || e.defaultPrevented || !trapStack.isTop(token)) {
        return;
      }
      const items = focusables();
      if (items.length === 0) {
        e.preventDefault();
        node.focus();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      // The container itself (where focus lands when nothing better exists)
      // counts as "before the first control": Shift+Tab from it must wrap,
      // not walk out to the page behind.
      const outside = !active || !node.contains(active) || active === node;
      if (e.shiftKey) {
        if (active === first || outside) {
          e.preventDefault();
          last.focus();
        }
      } else if (active === last || outside) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      node.removeEventListener("focusin", onFocusIn);
      observer.disconnect();
      remove();
      // A dialog still in the document is not closing: this is StrictMode's
      // simulated unmount (dev), whose re-run would then find focus outside
      // the dialog and take it off the autofocused field. A real close
      // removes the node before passive cleanups run.
      if (node.isConnected) return;
      // Return focus to where it was before the modal opened. An opener
      // that left the DOM (a menu item, unmounted with its menu) falls back
      // to the menu's trigger; neither is focused once detached.
      const target = returnTargets?.find(
        (el) => el !== document.body && el.isConnected,
      );
      target?.focus?.();
    };
  }, [seq]);
  return ref;
}

/** Where focus goes back to when a dialog closes, best first. */
type FocusReturnTargets = HTMLElement[];

/** The return targets of each open dialog's card (see `useFocusTrap`). */
const cardReturnTargets = new WeakMap<HTMLElement, FocusReturnTargets>();

/** The focused element, plus — when it is an item in an ARIA menu — the
 *  button that controls that menu. A dialog opened from a menu item outlives
 *  the item (the menu closes as the dialog opens), so the trigger is the
 *  operator's place in the page. Resolved now, while the menu is still open
 *  and its trigger still carries ``aria-controls``. */
function captureFocusReturnTargets(): FocusReturnTargets {
  if (typeof document === "undefined") return [];
  const active = document.activeElement as HTMLElement | null;
  if (!active) return [];
  const targets = [active];
  // Focus is on a dialog's own card: this dialog replaces that one, so what
  // that one would have returned to is where this one returns to as well.
  const inherited = cardReturnTargets.get(active);
  if (inherited) targets.push(...inherited);
  const menu = active.closest<HTMLElement>('[role="menu"][id]');
  if (menu) {
    const trigger = Array.from(
      document.querySelectorAll<HTMLElement>("[aria-controls]"),
    ).find((el) =>
      (el.getAttribute("aria-controls") ?? "").split(/\s+/).includes(menu.id),
    );
    if (trigger) targets.push(trigger);
  }
  return targets;
}

/** Rendered and focusable: no `hidden` / `display:none` / `visibility:hidden`
 *  between the element and the dialog. Computed style, not `offsetParent`,
 *  so it holds for `position: fixed` content and under jsdom. */
function isVisible(el: HTMLElement, root: HTMLElement): boolean {
  for (let n: HTMLElement | null = el; n; n = n.parentElement) {
    if (n.hidden) return false;
    const cs = getComputedStyle(n);
    if (cs.display === "none" || cs.visibility === "hidden") return false;
    if (n === root) break;
  }
  return true;
}

/**
 * The shared ``Modal``'s dialog contract, for a shell that draws its own
 * card (#1156): the custom shapes built on ``useDraggableModal`` +
 * ``MODAL_BACKDROP_CLS``, and the page-local overlays. ``Modal`` gives its
 * card ``role="dialog"``, ``aria-modal`` and a name, traps focus, and closes
 * on Esc. A shell without them was announced as a heading and an unnamed
 * button, and page code asking "is a dialog open?" — the shortcuts
 * overlay's stacking guard, the DNS zone's ``n`` shortcut — could not see
 * it, so a second dialog could open on top.
 *
 * Spread ``dialogProps`` on the card, ``titleProps`` on its heading (the
 * dialog is named by it), and give an icon-only close button
 * ``aria-label="Close dialog"`` as ``Modal`` does. A shell that drags also
 * puts ``dialogStyle`` on the card and ``dragHandleProps`` on its title
 * bar; one that never dragged leaves both off and keeps its layout. Esc
 * closes either (bound by ``useDraggableModal``).
 */
export function useModalDialog(onClose: () => void) {
  const { dialogStyle, dragHandleProps } = useDraggableModal(onClose);
  const ref = useFocusTrap<HTMLDivElement>();
  const titleId = useId();
  return {
    dialogProps: {
      ref,
      role: "dialog",
      "aria-modal": true,
      "aria-labelledby": titleId,
    } as const,
    titleProps: { id: titleId },
    dialogStyle,
    dragHandleProps,
  };
}
