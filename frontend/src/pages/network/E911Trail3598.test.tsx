/**
 * @vitest-environment jsdom
 *
 * The E911 Trail tab (#3598): offered only to an account that can read
 * `e911_resolution_log`, renders lookups and counter rows, and passes filters.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const trail = vi.fn();
let grants = new Set<string>();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    e911Api: {
      ...actual.e911Api,
      listErls: () =>
        Promise.resolve({ items: [], total: 0, limit: 50, offset: 0 }),
      listBindings: () =>
        Promise.resolve({ items: [], total: 0, limit: 50, offset: 0 }),
      listResolutionLog: (p: unknown) => trail(p),
    },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: (_a: string, r: string) => grants.has(r),
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

const { E911Page } = await import("@/pages/network/E911Page");

const row = (over: Record<string, unknown>) => ({
  id: "r1",
  kind: "lookup",
  queried_at: "2026-11-01T10:00:00Z",
  identity_kind: "ip",
  identity_value: "10.0.0.7",
  actor_kind: "api_token",
  actor_id: "t1",
  actor_label: "pbx-token",
  source_ip: "192.0.2.9",
  erl_id: "e1",
  erl_name: "HQ Lobby",
  rule_matched: "subnet",
  confidence: "degraded",
  degraded_reason: "port evidence stale",
  evidence_age_seconds: 900,
  window_start: null,
  suppressed_count: null,
  ...over,
});

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <E911Page />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  trail.mockReset();
  grants = new Set();
});

describe("E911 Trail tab", { timeout: 30000 }, () => {
  it("is not offered without read on e911_resolution_log", () => {
    grants = new Set(["e911_location"]);
    renderPage();
    expect(screen.queryByText("Trail")).toBeNull();
    expect(trail).not.toHaveBeenCalled();
  });

  it("lists lookups and counter rows and sends the identity filter", async () => {
    grants = new Set(["e911_resolution_log"]);
    trail.mockResolvedValue({
      items: [
        row({}),
        row({
          id: "r2",
          kind: "counter",
          suppressed_count: 7,
          erl_name: null,
          rule_matched: null,
        }),
      ],
      total: 2,
      limit: 50,
      offset: 0,
    });
    renderPage();
    fireEvent.click(screen.getByText("Trail"));
    expect(
      await screen.findByText("HQ Lobby", {}, { timeout: 10000 }),
    ).toBeTruthy();
    expect(screen.getAllByText("pbx-token").length).toBe(2);
    expect(screen.getAllByText("port evidence stale").length).toBeGreaterThan(
      0,
    );
    expect(screen.getByText(/7 lookups not individually logged/)).toBeTruthy();

    fireEvent.change(screen.getByPlaceholderText(/IP, MAC or port/), {
      target: { value: "10.0.0.7" },
    });
    await waitFor(
      () =>
        expect(trail).toHaveBeenLastCalledWith(
          expect.objectContaining({ identity: "10.0.0.7", offset: 0 }),
        ),
      { timeout: 10000 },
    );
  });
});
