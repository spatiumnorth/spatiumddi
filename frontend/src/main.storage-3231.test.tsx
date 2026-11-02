/**
 * @vitest-environment jsdom
 *
 * #3231 — the console starts when the browser refuses web storage.
 *
 * With site data blocked for the console's origin, Chrome and Edge throw a
 * ``SecurityError`` from the ``window.localStorage`` getter itself. main.tsx
 * reads the saved theme before it renders anything, so that throw left the
 * page an empty ``<div id="root">`` on every route, ``/login`` included. The
 * theme is only a preference: storage the browser refuses reads as "nothing
 * saved", and the system preference applies.
 *
 * ``createRoot`` is replaced by a recorder and ``App`` by a stub, so importing
 * the entry point runs what a page load runs, up to the first render.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { render } = vi.hoisted(() => ({ render: vi.fn() }));

vi.mock("react-dom/client", () => ({
  createRoot: () => ({ render }),
}));
vi.mock("./App", () => ({ default: () => null }));

const LOCAL_STORAGE = Object.getOwnPropertyDescriptor(window, "localStorage")!;

let systemDark = false;

function blockSiteData() {
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    get() {
      throw new DOMException(
        "Failed to read the 'localStorage' property from 'Window': Access is denied for this document.",
        "SecurityError",
      );
    },
  });
}

/** A fresh page load: main.tsx runs again from the top. */
async function loadConsole() {
  vi.resetModules();
  await import("./main");
}

const dark = () => document.documentElement.classList.contains("dark");

beforeEach(() => {
  document.body.innerHTML = '<div id="root"></div>';
  document.documentElement.classList.remove("dark");
  render.mockClear();
  systemDark = false;
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: systemDark && query === "(prefers-color-scheme: dark)",
    media: query,
  }));
});

afterEach(() => {
  Object.defineProperty(window, "localStorage", LOCAL_STORAGE);
  localStorage.clear();
  vi.unstubAllGlobals();
});

describe("the console's entry point with site data blocked (#3231)", () => {
  it("renders, in the system's dark theme", async () => {
    systemDark = true;
    blockSiteData();
    await loadConsole();
    expect(render).toHaveBeenCalledTimes(1);
    expect(dark()).toBe(true);
  });

  it("renders, in the system's light theme", async () => {
    systemDark = false;
    blockSiteData();
    await loadConsole();
    expect(render).toHaveBeenCalledTimes(1);
    expect(dark()).toBe(false);
  });
});

describe("the console's entry point with storage working (control)", () => {
  it("applies the saved theme over the system's before the first render", async () => {
    localStorage.setItem("theme", "dark");
    systemDark = false;
    await loadConsole();
    expect(render).toHaveBeenCalledTimes(1);
    expect(dark()).toBe(true);

    localStorage.setItem("theme", "light");
    systemDark = true;
    await loadConsole();
    expect(dark()).toBe(false);
  });

  it("follows the system with nothing saved", async () => {
    systemDark = true;
    await loadConsole();
    expect(dark()).toBe(true);
  });
});
