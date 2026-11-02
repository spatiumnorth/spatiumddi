import { useCallback, useEffect } from "react";
import type { FocusEvent, RefObject } from "react";

/**
 * The close contract every popover menu shares (#2047, #2061, #3159):
 * Esc closes it however it was opened and hands focus back to its
 * trigger, a mousedown elsewhere closes it, and focus moving to
 * something outside it closes it, so two menus are never open at once.
 *
 * Extracted from `HeaderMenu`, which had it first, so the pickers that
 * are not a list of actions (a filter-mode picker, the saved-views
 * panel, a checkbox list) read the same definition instead of each
 * hand-rolling an outside-mousedown listener and forgetting Esc.
 *
 * Spread the returned `onBlur` on the container element that wraps the
 * trigger and the panel.
 */
export function useDismissableMenu({
  open,
  onClose,
  containerRef,
  triggerRef,
}: {
  open: boolean;
  /** Close the menu. Called for Esc, an outside press and a focus move. */
  onClose: () => void;
  /** Wraps the trigger AND the panel. */
  containerRef: RefObject<HTMLElement | null>;
  /** Receives focus on Esc. Without it focus stays where it was. */
  triggerRef?: RefObject<HTMLElement | null>;
}) {
  useEffect(() => {
    if (!open) return;
    const onDocMouseDown = (e: MouseEvent) => {
      if (
        containerRef.current &&
        !containerRef.current.contains(e.target as Node)
      ) {
        onClose();
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
    // layer and so is the Esc. The blur handler on the container
    // normally closes the menu before that can happen; this is the
    // backstop, so a missed blur cannot yank focus back behind the
    // layer the operator is in.
    const onDocKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.isComposing) return;
      const active = document.activeElement;
      const inMenu =
        !active ||
        active === document.body ||
        (containerRef.current?.contains(active) ?? false);
      if (!inMenu) return;
      e.preventDefault();
      e.stopPropagation();
      onClose();
      triggerRef?.current?.focus();
    };
    document.addEventListener("mousedown", onDocMouseDown);
    document.addEventListener("keydown", onDocKeyDown, true);
    return () => {
      document.removeEventListener("mousedown", onDocMouseDown);
      document.removeEventListener("keydown", onDocKeyDown, true);
    };
  }, [open, onClose, containerRef, triggerRef]);

  // Focus leaving the menu for somewhere else closes it, so an open
  // menu never sits under whatever took focus (a Tab off a mouse-opened
  // trigger, or a layer that focused itself). A null relatedTarget is
  // focus going nowhere — a click on the page, the window losing focus
  // — which the outside-mousedown handler already decides.
  const onBlur = useCallback(
    (e: FocusEvent<HTMLElement>) => {
      const next = e.relatedTarget as Node | null;
      if (open && next && !e.currentTarget.contains(next)) onClose();
    },
    [open, onClose],
  );

  return { onBlur };
}
