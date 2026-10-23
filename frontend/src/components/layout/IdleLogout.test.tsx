/**
 * @vitest-environment jsdom
 *
 * Settings → Sessions in the console: the Auto-Logout Warning appears before
 * the Session Timeout, interaction dismisses it, the console signs out when
 * the timeout runs out, and 0 disables both. Every API request reports how
 * long the operator has been idle, so a background poll is not activity.
 */

import { act, cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const calls = { settings: vi.fn(), me: vi.fn(), logout: vi.fn() };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    settingsApi: { ...actual.settingsApi, get: () => calls.settings() },
    authApi: {
      ...actual.authApi,
      me: () => calls.me(),
      logout: () => calls.logout(),
    },
  };
});

import {
  IDLE_HEADER,
  idleHeader,
  idleSchedule,
  noteInteraction,
} from "@/lib/activity";
import { getAccessToken, setAccessToken } from "@/lib/authToken";
import { IdleLogout } from "./IdleLogout";

let base = Date.UTC(2030, 0, 1);

beforeEach(() => {
  // Each test starts on a later clock so module-level state from the last
  // one never reads as being in the future.
  base += 24 * 3600 * 1000;
  vi.useFakeTimers({ now: base });
  window.localStorage.clear();
  noteInteraction();
  setAccessToken("token");
  calls.me.mockResolvedValue({});
  calls.logout.mockResolvedValue({});
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  for (const f of Object.values(calls)) f.mockReset();
});

async function mount(timeout: number, warning: number) {
  calls.settings.mockResolvedValue({
    session_timeout_minutes: timeout,
    auto_logout_minutes: warning,
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <IdleLogout />
    </QueryClientProvider>,
  );
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
}

async function idleFor(seconds: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(seconds * 1000);
  });
}

describe("idleSchedule", () => {
  it("0 disables the timeout", () => {
    expect(idleSchedule(0, 5)).toBeNull();
  });
  it("0 disables only the warning", () => {
    expect(idleSchedule(60, 0)).toEqual({ warnAt: null, logoutAt: 3600 });
  });
  it("warns the configured minutes before expiry", () => {
    expect(idleSchedule(60, 5)).toEqual({ warnAt: 3300, logoutAt: 3600 });
  });
  it("never warns for more than half the timeout", () => {
    expect(idleSchedule(2, 5)).toEqual({ warnAt: 60, logoutAt: 120 });
  });
});

describe("IdleLogout", () => {
  it("warns, then signs out when the timeout runs out", async () => {
    await mount(2, 1);
    await idleFor(50);
    expect(screen.queryByText("Session about to expire")).toBeNull();

    await idleFor(15);
    expect(screen.getByText("Session about to expire")).toBeTruthy();
    expect(getAccessToken()).toBe("token");

    await idleFor(60);
    expect(getAccessToken()).toBeNull();
  });

  it("interaction dismisses the warning and restarts the clock", async () => {
    await mount(2, 1);
    await idleFor(65);
    expect(screen.getByText("Session about to expire")).toBeTruthy();

    act(() => {
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "a" }));
    });
    await idleFor(1);
    expect(screen.queryByText("Session about to expire")).toBeNull();

    await idleFor(100);
    expect(getAccessToken()).toBe("token");
  });

  it("0 never signs out", async () => {
    await mount(0, 5);
    await idleFor(6 * 3600);
    expect(screen.queryByText("Session about to expire")).toBeNull();
    expect(getAccessToken()).toBe("token");
  });

  it("signs out without a warning when the warning is 0", async () => {
    await mount(1, 0);
    await idleFor(59);
    expect(screen.queryByText("Session about to expire")).toBeNull();
    expect(getAccessToken()).toBe("token");
    await idleFor(2);
    expect(getAccessToken()).toBeNull();
  });
});

describe("idle header", () => {
  it("reports seconds since the last interaction", () => {
    vi.advanceTimersByTime(30_000);
    expect(idleHeader()).toEqual({ [IDLE_HEADER]: "30" });
    noteInteraction();
    expect(idleHeader()).toEqual({ [IDLE_HEADER]: "0" });
  });
});
