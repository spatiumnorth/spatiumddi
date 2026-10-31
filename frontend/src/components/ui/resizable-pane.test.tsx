/**
 * @vitest-environment jsdom
 *
 * ResizablePane (#3196) — the tree panes on IPAM / DNS / DHCP / VLANs /
 * Settings were fixed-width columns, so long names were cut off with no way
 * out. The failure modes worth pinning are the ones review and `tsc` pass
 * over: a drag that does not clamp, a width that does not come back after a
 * reload, a localStorage that throws taking the page down with it.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { ResizablePane } from "./resizable-pane";

// jsdom has no PointerEvent, so fireEvent.pointer* would drop clientX/button.
if (typeof window.PointerEvent === "undefined") {
  class PointerEventShim extends MouseEvent {
    pointerId: number;
    constructor(type: string, init: PointerEventInit = {}) {
      super(type, init);
      this.pointerId = init.pointerId ?? 0;
    }
  }
  (window as unknown as { PointerEvent: unknown }).PointerEvent =
    PointerEventShim;
}

const mqlListeners = new Set<() => void>();

function setViewport(width: number) {
  Object.defineProperty(window, "innerWidth", {
    configurable: true,
    value: width,
  });
  window.matchMedia = ((query: string) => ({
    // A getter, like the real MediaQueryList: listeners re-read it.
    get matches() {
      return window.innerWidth >= 768;
    },
    media: query,
    addEventListener: (_: string, fn: () => void) => mqlListeners.add(fn),
    removeEventListener: (_: string, fn: () => void) => mqlListeners.delete(fn),
    addListener: () => {},
    removeListener: () => {},
    onchange: null,
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}

/** Resize the window: media-query listeners and `resize` both fire. */
function resizeWindow(width: number) {
  setViewport(width);
  act(() => {
    mqlListeners.forEach((fn) => fn());
    window.dispatchEvent(new Event("resize"));
  });
}

beforeEach(() => {
  window.localStorage.clear();
  setViewport(1600);
});
afterEach(() => {
  cleanup();
  mqlListeners.clear();
  vi.restoreAllMocks();
});

const pane = (key = "t") => (
  <ResizablePane storageKey={key} defaultWidth={288} label="Resize tree">
    <span>tree</span>
  </ResizablePane>
);
const sep = () => screen.getByRole("separator", { name: "Resize tree" });
const now = () => Number(sep().getAttribute("aria-valuenow"));

describe("ResizablePane", () => {
  it("renders the separator with its ARIA contract at the default width", () => {
    render(pane());
    expect(sep().getAttribute("aria-orientation")).toBe("vertical");
    expect(sep().getAttribute("tabindex")).toBe("0");
    expect(now()).toBe(288);
    expect(sep().getAttribute("aria-valuemin")).toBe("192");
    expect(sep().getAttribute("aria-valuemax")).toBe("640");
  });

  it("drags to a new width, clamps both ends, and sets/clears the body cursor", () => {
    render(pane());
    fireEvent.pointerDown(sep(), { clientX: 300, pointerId: 1, button: 0 });
    expect(document.body.style.cursor).toBe("col-resize");
    expect(document.body.style.userSelect).toBe("none");
    fireEvent.pointerMove(sep(), { clientX: 400, pointerId: 1 });
    expect(now()).toBe(388);
    fireEvent.pointerMove(sep(), { clientX: 5000, pointerId: 1 });
    expect(now()).toBe(640);
    fireEvent.pointerMove(sep(), { clientX: -5000, pointerId: 1 });
    expect(now()).toBe(192);
    fireEvent.pointerUp(sep(), { pointerId: 1 });
    expect(document.body.style.cursor).toBe("");
    fireEvent.pointerMove(sep(), { clientX: 500, pointerId: 1 });
    expect(now()).toBe(192);
  });

  it("caps the maximum at half the viewport on a narrower window", () => {
    setViewport(900);
    render(pane());
    expect(sep().getAttribute("aria-valuemax")).toBe("450");
  });

  it("resizes with the arrow keys, Shift for bigger steps, Home/End", () => {
    render(pane());
    fireEvent.keyDown(sep(), { key: "ArrowRight" });
    expect(now()).toBe(304);
    fireEvent.keyDown(sep(), { key: "ArrowLeft", shiftKey: true });
    expect(now()).toBe(240);
    fireEvent.keyDown(sep(), { key: "Home" });
    expect(now()).toBe(192);
    fireEvent.keyDown(sep(), { key: "ArrowLeft" });
    expect(now()).toBe(192);
    fireEvent.keyDown(sep(), { key: "End" });
    expect(now()).toBe(640);
  });

  it("resets to the default on double-click and forgets the stored width", () => {
    render(pane());
    fireEvent.keyDown(sep(), { key: "End" });
    expect(window.localStorage.getItem("spatium.paneWidth.t")).toBe("640");
    fireEvent.doubleClick(sep());
    expect(now()).toBe(288);
    expect(window.localStorage.getItem("spatium.paneWidth.t")).toBeNull();
  });

  it("restores the persisted width, clamped, per key", () => {
    window.localStorage.setItem("spatium.paneWidth.a", "400");
    window.localStorage.setItem("spatium.paneWidth.b", "99999");
    const { unmount } = render(pane("a"));
    expect(now()).toBe(400);
    unmount();
    render(pane("b"));
    expect(now()).toBe(640);
  });

  it("still renders and resizes when localStorage throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    render(pane());
    expect(now()).toBe(288);
    fireEvent.keyDown(sep(), { key: "ArrowRight" });
    expect(now()).toBe(304);
  });

  it("persists a drag once, when it ends, not on every move", () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    render(pane());
    fireEvent.pointerDown(sep(), { clientX: 300, pointerId: 1, button: 0 });
    fireEvent.pointerMove(sep(), { clientX: 350, pointerId: 1 });
    fireEvent.pointerMove(sep(), { clientX: 400, pointerId: 1 });
    expect(setItem).not.toHaveBeenCalled();
    fireEvent.pointerUp(sep(), { pointerId: 1 });
    expect(setItem).toHaveBeenCalledTimes(1);
    expect(window.localStorage.getItem("spatium.paneWidth.t")).toBe("388");
  });

  it.each([
    ["lostpointercapture", () => fireEvent.lostPointerCapture(sep())],
    ["pointercancel", () => fireEvent.pointerCancel(sep(), { pointerId: 1 })],
    [
      "window blur",
      () => act(() => void window.dispatchEvent(new Event("blur"))),
    ],
  ])("a drag ended by %s restores the body and keeps the width", (_, end) => {
    render(pane());
    fireEvent.pointerDown(sep(), { clientX: 300, pointerId: 1, button: 0 });
    fireEvent.pointerMove(sep(), { clientX: 400, pointerId: 1 });
    end();
    expect(document.body.style.cursor).toBe("");
    expect(document.body.style.userSelect).toBe("");
    expect(window.localStorage.getItem("spatium.paneWidth.t")).toBe("388");
    // No button held any more: a stray move must not resize.
    fireEvent.pointerMove(sep(), { clientX: 500, pointerId: 1 });
    expect(now()).toBe(388);
  });

  it("restores the body cursor when the pane unmounts mid-drag", () => {
    const { unmount } = render(pane());
    fireEvent.pointerDown(sep(), { clientX: 300, pointerId: 1, button: 0 });
    expect(document.body.style.cursor).toBe("col-resize");
    unmount();
    expect(document.body.style.cursor).toBe("");
    expect(document.body.style.userSelect).toBe("");
  });

  it("restores the body cursor when the window narrows below md mid-drag", () => {
    render(pane());
    fireEvent.pointerDown(sep(), { clientX: 300, pointerId: 1, button: 0 });
    resizeWindow(600);
    expect(screen.queryByRole("separator")).toBeNull();
    expect(document.body.style.cursor).toBe("");
    resizeWindow(1600);
    // Back on desktop the old drag is gone: hovering must not resize.
    fireEvent.pointerMove(sep(), { clientX: 900, pointerId: 1 });
    expect(now()).toBe(288);
  });

  it("shrinks a stored width when the window narrows, and regrows it", () => {
    window.localStorage.setItem("spatium.paneWidth.t", "600");
    render(pane());
    expect(now()).toBe(600);
    resizeWindow(900);
    expect(now()).toBe(450);
    expect(sep().getAttribute("aria-valuemax")).toBe("450");
    resizeWindow(1600);
    expect(now()).toBe(600);
  });

  it("crossing md keeps the tree mounted, so its state survives", () => {
    function Counter() {
      const [n, setN] = useState(0);
      return <button onClick={() => setN(n + 1)}>clicked {n}</button>;
    }
    render(
      <ResizablePane storageKey="t" defaultWidth={288} label="Resize tree">
        <Counter />
      </ResizablePane>,
    );
    fireEvent.click(screen.getByRole("button"));
    resizeWindow(600);
    resizeWindow(1600);
    expect(screen.getByRole("button").textContent).toBe("clicked 1");
  });

  it("below md it is the old fixed pane: no handle, default width", () => {
    setViewport(500);
    const { container } = render(pane());
    expect(screen.queryByRole("separator")).toBeNull();
    expect((container.firstElementChild as HTMLElement).style.width).toBe(
      "288px",
    );
  });
});

describe("the five tree pages", () => {
  const pages = [
    "pages/ipam/IPAMPage.tsx",
    "pages/dns/DNSPage.tsx",
    "pages/dhcp/DHCPPage.tsx",
    "pages/vlans/VLANsPage.tsx",
    "pages/SettingsPage.tsx",
  ];
  // Prop order and formatting are free; what matters is that each page
  // mounts the shared pane under its own storage key.
  const keyOf = (rel: string) => {
    const src = readFileSync(resolve(__dirname, "../../", rel), "utf8");
    return /<ResizablePane\b[^>]*?\bstorageKey="([^"]+)"/.exec(src)?.[1];
  };
  it.each(pages)("%s mounts its tree in a ResizablePane", (rel) => {
    expect(keyOf(rel)).toBeTruthy();
  });
  it("each page remembers its own width", () => {
    const keys = pages.map(keyOf);
    expect(new Set(keys).size).toBe(pages.length);
  });
});
