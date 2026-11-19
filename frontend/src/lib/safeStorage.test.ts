/**
 * @vitest-environment jsdom
 *
 * #3231 — web storage that never throws. A browser can refuse storage in two
 * ways: with site data blocked, Chrome and Edge throw a ``SecurityError`` from
 * the ``window.localStorage`` / ``window.sessionStorage`` getters themselves;
 * with the quota full, every ``setItem`` throws a ``QuotaExceededError``. A
 * refused read is "nothing saved" and a refused write is dropped. With storage
 * working these are the browser's own reads and writes.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { safeLocalStorage, safeSessionStorage } from "./safeStorage";

type Area = "localStorage" | "sessionStorage";

const ORIGINAL: Record<Area, PropertyDescriptor> = {
  localStorage: Object.getOwnPropertyDescriptor(window, "localStorage")!,
  sessionStorage: Object.getOwnPropertyDescriptor(window, "sessionStorage")!,
};

function blockSiteData(area: Area) {
  Object.defineProperty(window, area, {
    configurable: true,
    get() {
      throw new DOMException(
        `Failed to read the '${area}' property from 'Window': Access is denied for this document.`,
        "SecurityError",
      );
    },
  });
}

function fillStorage() {
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
    throw new DOMException(
      "Failed to execute 'setItem' on 'Storage': Setting the value exceeded the quota.",
      "QuotaExceededError",
    );
  });
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const area of ["localStorage", "sessionStorage"] as const) {
    Object.defineProperty(window, area, ORIGINAL[area]);
  }
  localStorage.clear();
  sessionStorage.clear();
});

describe.each([
  ["localStorage", safeLocalStorage],
  ["sessionStorage", safeSessionStorage],
] as const)("%s", (area, store) => {
  it("reads and writes the browser's store", () => {
    expect(store.getItem("k")).toBeNull();
    store.setItem("k", "v");
    expect(window[area].getItem("k")).toBe("v");
    expect(store.getItem("k")).toBe("v");
  });

  it("reads nothing and drops the write with site data blocked", () => {
    window[area].setItem("k", "v");
    blockSiteData(area);
    expect(store.getItem("k")).toBeNull();
    expect(() => store.setItem("k", "w")).not.toThrow();
  });

  it("drops the write with storage full, and still reads", () => {
    window[area].setItem("k", "v");
    fillStorage();
    expect(() => store.setItem("k", "w")).not.toThrow();
    expect(store.getItem("k")).toBe("v");
  });
});
