/**
 * @vitest-environment jsdom
 *
 * A failed events or rules read is not drawn as an empty answer (#3829), and
 * more than one page of open events is reachable and counted (#3830).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";

const perms = { is_superadmin: true, grants: [] };
const state: {
  events: (p: { offset?: number }) => Promise<unknown>;
  rules: () => Promise<unknown>;
} = {
  events: async () => ({ items: [], total: 0 }),
  rules: async () => [],
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) => {
              if (typeof method === "symbol") return undefined;
              if (name === "authApi" && method === "myPermissions")
                return async () => perms;
              if (name === "alertsApi" && method === "listRules")
                return () => state.rules();
              if (name === "alertsApi" && method === "listEventsPage")
                return (p: { offset?: number }) => state.events(p);
              return pending;
            },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { AlertsPage } = await import("./AlertsPage");

afterEach(cleanup);

function show() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/admin/alerts"]}>
        <Routes>
          <Route path="/admin/alerts" element={<AlertsPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const ev = (i: number) => ({
  id: `e${i}`,
  rule_id: "r",
  subject_type: "subnet",
  subject_id: `s${i}`,
  severity: "info",
  message: `msg-${i}`,
  fired_at: "2026-11-03T00:00:00.000Z",
  resolved_at: null,
});

describe("AlertsPage failed reads (#3829)", () => {
  it("says the events and rules reads failed, not all-clear", async () => {
    state.events = async () => {
      throw new Error("boom");
    };
    state.rules = async () => {
      throw new Error("boom");
    };
    show();
    expect(await screen.findByText(/Couldn't load alert events/)).toBeTruthy();
    expect(await screen.findByText(/Couldn't load alert rules/)).toBeTruthy();
    expect(screen.queryByText(/all clear/)).toBeNull();
    expect(screen.queryByText(/No rules yet/)).toBeNull();
  });
});

describe("AlertsPage paging (#3830)", () => {
  it("says how many of the total it shows and loads the rest", async () => {
    state.rules = async () => [];
    state.events = async (p) =>
      (p.offset ?? 0) === 0
        ? { items: [ev(1), ev(2)], total: 3 }
        : { items: [ev(3)], total: 3 };
    show();
    expect(await screen.findByText("2 of 3 shown")).toBeTruthy();
    fireEvent.click(await screen.findByText("Load more"));
    expect(await screen.findByText("msg-3")).toBeTruthy();
    expect(await screen.findByText("3 shown")).toBeTruthy();
    expect(screen.queryByText("Load more")).toBeNull();
  });
});
