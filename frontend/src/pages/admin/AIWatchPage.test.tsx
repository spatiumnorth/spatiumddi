/**
 * @vitest-environment jsdom
 *
 * Copilot Watch page (#4405): the findings inbox, the status pill, and the
 * superadmin-only controls and Settings tab.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const state = {
  superadmin: false,
  grants: [] as { action: string; resource_type: string }[],
  paused: false,
};
const finding = {
  id: "f1",
  fingerprint: "fp",
  kind: "server",
  severity: "critical",
  title: "DNS server ns1 is unreachable",
  explanation: "ns1 stopped answering health checks.",
  evidence: [],
  recommendations: [],
  confidence: "high",
  state: "open",
  first_seen_at: "2026-11-18T00:00:00Z",
  last_seen_at: "2026-11-18T00:00:00Z",
  resolved_at: null,
  run_id: null,
  model: "m",
  state_changed_at: null,
  state_changed_by: null,
  state_note: "",
  my_verdict: null,
  feedback: [],
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: async () => ({
        is_superadmin: state.superadmin,
        grants: state.grants.map((g) => ({
          ...g,
          resource_id: null,
        })),
      }),
    },
    aiWatchApi: {
      ...actual.aiWatchApi,
      summary: async () => ({
        enabled: true,
        paused: state.paused,
        paused_reason: state.paused ? "manual" : null,
        paused_detail: "",
        paused_until: null,
        open_total: 1,
        open_by_severity: { critical: 1 },
        acknowledged_total: 0,
        last_run: null,
      }),
      listFindings: async () => ({ items: [finding], total: 1 }),
      listRuns: async () => ({ items: [], total: 0 }),
    },
  };
});

import { AIWatchPage } from "./AIWatchPage";

function renderPage() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <AIWatchPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
afterEach(cleanup);

describe("Copilot Watch page (#4405)", { timeout: 30000 }, () => {
  it("shows the inbox and a Watching pill to a reader, without superadmin controls", async () => {
    state.superadmin = false;
    state.paused = false;
    state.grants = [{ action: "read", resource_type: "ai_finding" }];
    renderPage();
    expect(
      await screen.findByText("DNS server ns1 is unreachable"),
    ).toBeTruthy();
    expect((await screen.findByTestId("watch-status")).textContent).toBe(
      "Watching",
    );
    expect(screen.queryByRole("button", { name: /Run now/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Settings" })).toBeNull();
  });

  it("offers Run now, Pause and Settings to a superadmin", async () => {
    state.superadmin = true;
    state.paused = false;
    renderPage();
    expect(await screen.findByRole("button", { name: /Run now/ })).toBeTruthy();
    expect(await screen.findByRole("button", { name: /Pause/ })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Settings" })).toBeTruthy();
  });

  it("says Paused and offers Resume while paused", async () => {
    state.superadmin = true;
    state.paused = true;
    renderPage();
    expect(await screen.findByRole("button", { name: /Resume/ })).toBeTruthy();
    expect((await screen.findByTestId("watch-status")).textContent).toMatch(
      /Paused/,
    );
  });

  it("disables Acknowledge for a reader without write", async () => {
    state.superadmin = false;
    state.paused = false;
    state.grants = [{ action: "read", resource_type: "ai_finding" }];
    renderPage();
    fireEvent.click(await screen.findByText("DNS server ns1 is unreachable"));
    const btn = (await screen.findByRole("button", {
      name: /Acknowledge/,
    })) as HTMLButtonElement;
    await vi.waitFor(() =>
      expect(btn.disabled || btn.getAttribute("aria-disabled") === "true").toBe(
        true,
      ),
    );
  });
});
