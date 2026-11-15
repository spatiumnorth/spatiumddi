import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";

/**
 * App-wide tooltip (#4210).
 *
 * The browser's native `title` tooltip waits about a second and the
 * delay cannot be changed, so small icon buttons read as unlabelled. Rather
 * than edit ~725 call sites (and every open PR that touches them), one
 * layer mounted at the app root takes the `title` text over:
 *
 *  - On pointer-over of an element with a `title` (nearest titled
 *    ancestor), a 300 ms timer starts. Keyboard focus (`:focus-visible`)
 *    shows it at once.
 *  - From the moment the tooltip is armed the `title` attribute is moved
 *    into `data-tooltip-title`, so the native tooltip never also appears,
 *    and it is put back on leave / hide / unmount. An element that is
 *    named only by its title keeps that name through a temporary
 *    `aria-label`; `aria-describedby` points at the tooltip while shown.
 *  - Esc, pointer leave, blur, scroll, pointer-down and the anchor leaving
 *    the DOM all hide it. It is `pointer-events: none`, so it never
 *    steals a click or a hover.
 *  - Disabled controls: browsers do not reliably dispatch pointer events
 *    on a disabled button, and the reason it carries (#3770) is exactly
 *    what the operator wants to read, so when the event target has no
 *    titled ancestor the layer hit-tests `elementsFromPoint` for a
 *    disabled titled element.
 *
 * Opt out per element with `data-native-title` (keeps the browser tooltip).
 * Elements whose title is empty are ignored.
 */

const SHOW_DELAY_MS = 300;
const GAP = 6;
const MARGIN = 8;
const ATTR = "data-tooltip-title";
const SELECTOR = `[title]:not([data-native-title]), [${ATTR}]`;

type Anchor = {
  el: HTMLElement;
  text: string;
  /** aria-label we added because the title was the only name. */
  addedLabel: boolean;
};

function titledAncestor(node: EventTarget | null): HTMLElement | null {
  if (!(node instanceof Element)) return null;
  const el = node.closest(SELECTOR);
  return el instanceof HTMLElement ? el : null;
}

function titleOf(el: HTMLElement): string {
  return (el.getAttribute(ATTR) ?? el.getAttribute("title") ?? "").trim();
}

function disabledAt(x: number, y: number): HTMLElement | null {
  if (typeof document.elementsFromPoint !== "function") return null;
  for (const el of document.elementsFromPoint(x, y)) {
    if (
      el instanceof HTMLElement &&
      el.matches(SELECTOR) &&
      el.matches(":disabled")
    )
      return el;
  }
  return null;
}

function keyboardFocus(el: HTMLElement): boolean {
  try {
    return el.matches(":focus-visible");
  } catch {
    // Engine without :focus-visible: treat focus as keyboard focus.
    return true;
  }
}

export function TooltipLayer() {
  const [shown, setShown] = useState<Anchor | null>(null);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);
  const tipRef = useRef<HTMLDivElement | null>(null);
  const anchorRef = useRef<Anchor | null>(null);
  const timer = useRef<number | undefined>(undefined);
  const suppressed = useRef<HTMLElement | null>(null);
  const pending = useRef<HTMLElement | null>(null);
  const id = useRef(`tooltip-${Math.random().toString(36).slice(2, 9)}`);

  /** Move title -> data attribute (idempotent) and return the anchor. */
  const arm = useCallback((el: HTMLElement): Anchor | null => {
    const title = el.getAttribute("title");
    if (title !== null) {
      // A re-render may have re-set the title after we armed: the live
      // attribute wins, ours is stale.
      el.setAttribute(ATTR, title);
      el.removeAttribute("title");
    }
    const text = titleOf(el);
    if (!text) return null;
    let addedLabel = false;
    if (
      !el.hasAttribute("aria-label") &&
      !el.hasAttribute("aria-labelledby") &&
      !(el.textContent ?? "").trim()
    ) {
      el.setAttribute("aria-label", text);
      addedLabel = true;
    }
    return { el, text, addedLabel };
  }, []);

  /** Undo `arm`: restore the native attribute, drop the temporary name. */
  const disarm = useCallback((a: Anchor) => {
    const { el } = a;
    const saved = el.getAttribute(ATTR);
    el.removeAttribute(ATTR);
    el.removeAttribute("aria-describedby");
    if (a.addedLabel) el.removeAttribute("aria-label");
    if (saved !== null && !el.hasAttribute("title"))
      el.setAttribute("title", saved);
  }, []);

  const hide = useCallback(() => {
    window.clearTimeout(timer.current);
    pending.current = null;
    const a = anchorRef.current;
    anchorRef.current = null;
    if (a) disarm(a);
    setShown(null);
    setPos(null);
  }, [disarm]);

  const show = useCallback(
    (el: HTMLElement) => {
      if (anchorRef.current?.el === el) return;
      hide();
      const a = arm(el);
      if (!a) return;
      anchorRef.current = a;
      el.setAttribute("aria-describedby", id.current);
      setShown(a);
    },
    [arm, hide],
  );

  const schedule = useCallback(
    (el: HTMLElement, immediate: boolean) => {
      if (anchorRef.current?.el === el || pending.current === el) return;
      window.clearTimeout(timer.current);
      pending.current = el;
      if (immediate) {
        show(el);
        return;
      }
      timer.current = window.setTimeout(() => show(el), SHOW_DELAY_MS);
    },
    [show],
  );

  useEffect(() => {
    // The native tooltip appears after ~1 s, ours after 300 ms; so the
    // title only has to be removed when we show. Restoring on leave is
    // therefore also only needed for a shown anchor.
    const resolve = (e: PointerEvent): HTMLElement | null =>
      titledAncestor(e.target) ?? disabledAt(e.clientX, e.clientY);

    const onMove = (e: PointerEvent) => {
      if (e.pointerType === "touch") return;
      const el = resolve(e);
      const cur = anchorRef.current?.el ?? pending.current;
      if (el !== suppressed.current) suppressed.current = null;
      if (el === cur || (el && el === suppressed.current)) return;
      if (!el) {
        hide();
        return;
      }
      // Moving between neighbouring controls while one tooltip is up
      // switches at once; a cold hover waits the delay.
      if (anchorRef.current) show(el);
      else {
        hide();
        schedule(el, false);
      }
    };
    const onOut = (e: PointerEvent) => {
      const cur = anchorRef.current?.el ?? pending.current;
      if (!cur) return;
      const to = e.relatedTarget;
      if (to instanceof Node && cur.contains(to)) return;
      if (!to) hide();
    };
    const onFocusIn = (e: FocusEvent) => {
      const el = titledAncestor(e.target);
      if (el && keyboardFocus(el)) {
        hide();
        schedule(el, true);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && anchorRef.current) hide();
    };

    document.addEventListener("pointermove", onMove, true);
    document.addEventListener("pointerover", onMove, true);
    document.addEventListener("pointerout", onOut, true);
    const onDown = (e: PointerEvent) => {
      // A click dismisses the tooltip for good until the pointer leaves
      // the control; otherwise it would reappear under the cursor.
      suppressed.current = titledAncestor(e.target);
      hide();
    };
    document.addEventListener("pointerdown", onDown, true);
    document.addEventListener("focusin", onFocusIn, true);
    document.addEventListener("focusout", hide, true);
    document.addEventListener("keydown", onKey, true);
    window.addEventListener("scroll", hide, true);
    window.addEventListener("blur", hide);
    return () => {
      document.removeEventListener("pointermove", onMove, true);
      document.removeEventListener("pointerover", onMove, true);
      document.removeEventListener("pointerout", onOut, true);
      document.removeEventListener("pointerdown", onDown, true);
      document.removeEventListener("focusin", onFocusIn, true);
      document.removeEventListener("focusout", hide, true);
      document.removeEventListener("keydown", onKey, true);
      window.removeEventListener("scroll", hide, true);
      window.removeEventListener("blur", hide);
      hide();
    };
  }, [hide, schedule]);

  // The anchor can be unmounted under a shown tooltip (a row deleted, a
  // dialog closed): no pointer event follows, so watch for it.
  useEffect(() => {
    if (!shown) return;
    const mo = new MutationObserver(() => {
      if (!shown.el.isConnected) hide();
    });
    mo.observe(document.body, { childList: true, subtree: true });
    return () => mo.disconnect();
  }, [shown, hide]);

  // Position after render, from the measured size: below the anchor,
  // flipped above when it would leave the viewport, clamped horizontally.
  useLayoutEffect(() => {
    if (!shown || !tipRef.current) return;
    const a = shown.el.getBoundingClientRect();
    const t = tipRef.current.getBoundingClientRect();
    const vw = document.documentElement.clientWidth;
    const vh = document.documentElement.clientHeight;
    let top = a.bottom + GAP;
    if (top + t.height > vh - MARGIN && a.top - GAP - t.height >= MARGIN)
      top = a.top - GAP - t.height;
    top = Math.max(MARGIN, Math.min(top, vh - t.height - MARGIN));
    let left = a.left + a.width / 2 - t.width / 2;
    left = Math.max(MARGIN, Math.min(left, vw - t.width - MARGIN));
    setPos({ left, top });
  }, [shown]);

  if (!shown) return null;
  return createPortal(
    <div
      ref={tipRef}
      id={id.current}
      role="tooltip"
      style={{
        position: "fixed",
        left: pos?.left ?? 0,
        top: pos?.top ?? 0,
        visibility: pos ? "visible" : "hidden",
        maxWidth: 240,
        zIndex: 100000,
        pointerEvents: "none",
      }}
      className="rounded-md border border-border bg-popover px-2 py-1 text-xs leading-snug text-popover-foreground shadow-md [overflow-wrap:anywhere]"
    >
      {shown.text}
    </div>,
    document.body,
  );
}
