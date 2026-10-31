import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
} from "react";

import { useMediaQuery } from "@/hooks/useMediaQuery";
import { cn } from "@/lib/utils";

/** Narrowest a pane may be dragged to: 12rem at the 16px root size. */
export const PANE_MIN_WIDTH = 192;
/** Widest a pane may be dragged to: 40rem, or half the viewport if smaller —
 *  the detail pane beside it must stay usable. */
export const PANE_MAX_WIDTH = 640;
const KEY_STEP = 16;
const KEY_STEP_LARGE = 64;
const STORAGE_PREFIX = "spatium.paneWidth.";

export function clampPaneWidth(width: number, viewportWidth: number): number {
  const max = Math.max(
    PANE_MIN_WIDTH,
    Math.min(PANE_MAX_WIDTH, Math.floor(viewportWidth / 2)),
  );
  return Math.min(max, Math.max(PANE_MIN_WIDTH, Math.round(width)));
}

function readStored(id: string): number | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_PREFIX + id);
    if (raw === null) return null;
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  } catch {
    // Private window / blocked storage: fall back to the default width.
    return null;
  }
}

function writeStored(id: string, width: number | null) {
  try {
    if (width === null) window.localStorage.removeItem(STORAGE_PREFIX + id);
    else window.localStorage.setItem(STORAGE_PREFIX + id, String(width));
  } catch {
    // Not persisting is harmless; the width still applies this session.
  }
}

/**
 * Width state for a resizable side pane (#3196): clamped, persisted per
 * `storageKey` in localStorage, reset to `defaultWidth` on demand. Nothing is
 * stored until the user actually resizes, so the default stays whatever the
 * page ships.
 */
export function useResizableWidth(storageKey: string, defaultWidth: number) {
  const vw = () => (typeof window === "undefined" ? 1280 : window.innerWidth);
  const [width, setWidthState] = useState<number>(() => {
    const stored = readStored(storageKey);
    return clampPaneWidth(stored ?? defaultWidth, vw());
  });
  const [viewport, setViewport] = useState<number>(vw);

  useEffect(() => {
    const onResize = () => setViewport(window.innerWidth);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const setWidth = useCallback(
    (next: number, persist = true) => {
      const clamped = clampPaneWidth(next, window.innerWidth);
      setWidthState(clamped);
      if (persist) writeStored(storageKey, clamped);
    },
    [storageKey],
  );
  const reset = useCallback(() => {
    setWidthState(clampPaneWidth(defaultWidth, window.innerWidth));
    writeStored(storageKey, null);
  }, [storageKey, defaultWidth]);

  const max = clampPaneWidth(Number.MAX_SAFE_INTEGER, viewport);
  return {
    // Re-clamp on render so a shrunken window never leaves the pane too wide.
    width: clampPaneWidth(width, viewport),
    min: PANE_MIN_WIDTH,
    max,
    setWidth,
    reset,
  };
}

interface ResizablePaneProps {
  /** Unique per page; the localStorage key suffix. */
  storageKey: string;
  /** Width in px used until the user drags — the pane's old fixed width. */
  defaultWidth: number;
  /** Accessible name of the drag handle, e.g. "Resize IP spaces tree". */
  label: string;
  /** Classes for the pane itself (border, background, overflow, flex). */
  className?: string;
  as?: "div" | "aside";
  children: ReactNode;
}

/**
 * A left-hand tree pane with a draggable right edge. Below `md` (where these
 * pages keep their fixed-width layout) the pane renders at `defaultWidth`
 * with no handle, exactly as before.
 */
export function ResizablePane({
  storageKey,
  defaultWidth,
  label,
  className,
  as: Tag = "div",
  children,
}: ResizablePaneProps) {
  const isDesktop = useMediaQuery("(min-width: 768px)");
  const { width, min, max, setWidth, reset } = useResizableWidth(
    storageKey,
    defaultWidth,
  );
  const drag = useRef<{ startX: number; startWidth: number } | null>(null);
  const [dragging, setDragging] = useState(false);

  // Col-resize cursor + no text selection for the length of a drag, even when
  // the pointer is over other elements.
  useEffect(() => {
    if (!dragging) return;
    const { cursor, userSelect } = document.body.style;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    return () => {
      document.body.style.cursor = cursor;
      document.body.style.userSelect = userSelect;
    };
  }, [dragging]);

  function onPointerDown(e: ReactPointerEvent<HTMLDivElement>) {
    if (e.button !== 0) return;
    e.preventDefault();
    e.currentTarget.setPointerCapture?.(e.pointerId);
    drag.current = { startX: e.clientX, startWidth: width };
    setDragging(true);
  }
  function onPointerMove(e: ReactPointerEvent<HTMLDivElement>) {
    if (!drag.current) return;
    setWidth(drag.current.startWidth + e.clientX - drag.current.startX);
  }
  function endDrag(e: ReactPointerEvent<HTMLDivElement>) {
    if (!drag.current) return;
    drag.current = null;
    setDragging(false);
    e.currentTarget.releasePointerCapture?.(e.pointerId);
  }
  function onKeyDown(e: ReactKeyboardEvent<HTMLDivElement>) {
    const step = e.shiftKey ? KEY_STEP_LARGE : KEY_STEP;
    let next: number | null = null;
    if (e.key === "ArrowLeft") next = width - step;
    else if (e.key === "ArrowRight") next = width + step;
    else if (e.key === "Home") next = min;
    else if (e.key === "End") next = max;
    if (next === null) return;
    e.preventDefault();
    setWidth(next);
  }

  if (!isDesktop) {
    return (
      <Tag
        className={cn("flex-shrink-0", className)}
        style={{ width: defaultWidth }}
      >
        {children}
      </Tag>
    );
  }

  return (
    <div className="relative flex flex-shrink-0" style={{ width }}>
      <Tag className={cn("min-w-0 flex-1", className)}>{children}</Tag>
      <div
        role="separator"
        aria-orientation="vertical"
        aria-label={label}
        aria-valuenow={width}
        aria-valuemin={min}
        aria-valuemax={max}
        tabIndex={0}
        title="Drag to resize, double-click to reset"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endDrag}
        onPointerCancel={endDrag}
        onDoubleClick={reset}
        onKeyDown={onKeyDown}
        className={cn(
          "absolute inset-y-0 -right-[3px] z-10 w-[7px] cursor-col-resize touch-none",
          "hover:bg-primary/30 focus-visible:bg-primary/40 focus-visible:outline-none",
          dragging && "bg-primary/40",
        )}
      />
    </div>
  );
}
