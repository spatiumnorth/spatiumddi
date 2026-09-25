import { useEffect, useId, useRef, useState } from "react";

/** CSS for the outer flex-center backdrop. Same across every modal. */
export const MODAL_BACKDROP_CLS =
  "fixed inset-0 z-50 flex items-center justify-center bg-black/20 p-2 sm:p-4";

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

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

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
 * dialog so keyboard focus can't escape to the page behind. On close focus
 * returns to wherever it was, so the operator's place in the page is kept.
 *
 * Lives next to ``useDraggableModal`` so every modal can opt in with one line.
 */
export function useFocusTrap<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;

    const focusables = () =>
      Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
        (el) => el.offsetParent !== null,
      );

    // Respect an existing autoFocus inside the dialog; otherwise focus the
    // dialog container itself (tabindex -1) so screen readers announce it and
    // the operator tabs into the content — never auto-landing on the close X.
    if (!node.contains(document.activeElement)) {
      node.setAttribute("tabindex", "-1");
      node.focus();
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Tab") return;
      const items = focusables();
      if (items.length === 0) {
        e.preventDefault();
        node.focus();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      if (e.shiftKey) {
        if (active === first || !node.contains(active)) {
          e.preventDefault();
          last.focus();
        }
      } else if (active === last || !node.contains(active)) {
        e.preventDefault();
        first.focus();
      }
    };
    node.addEventListener("keydown", onKeyDown);
    return () => {
      node.removeEventListener("keydown", onKeyDown);
      // Return focus to where it was before the modal opened (if still in DOM).
      previouslyFocused?.focus?.();
    };
  }, []);
  return ref;
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
