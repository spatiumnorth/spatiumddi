/**
 * @vitest-environment jsdom
 *
 * The History tab pages the decided requests with ``offset`` and says how many
 * it does not show (#4383); the Queue does the same past its first window.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import type { ChangeRequest } from "@/lib/api";

const TOTAL = 150;
const listPage = vi.fn(
  async (params: { states?: string[]; limit?: number; offset?: number }) => {
    const offset = params.offset ?? 0;
    const limit = params.limit ?? 100;
    const decided = params.states?.includes("executed");
    const n = decided ? TOTAL : 1;
    const items = Array.from(
      { length: Math.max(0, Math.min(limit, n - offset)) },
      (_, i) =>
        cr(
          `${decided ? "h" : "q"}${offset + i}`,
          decided ? "executed" : "pending",
        ),
    );
    return { items, total: n };
  },
);

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ id: "me" }) },
    changeRequestsApi: {
      ...actual.changeRequestsApi,
      listPage: (p: Parameters<typeof listPage>[0]) => listPage(p),
    },
  };
});

vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ can: () => true, isSuperadmin: false }),
}));

import { ChangeRequestsPage } from "./ChangeRequestsPage";

function cr(id: string, state: ChangeRequest["state"]): ChangeRequest {
  return {
    id,
    operation: `op-${id}`,
    resource_type: "dns_zone",
    resource_id: null,
    resource_display: id,
    args: {},
    preview_text: "p",
    risk_reason: "r",
    state,
    requested_by_user_id: "someone",
    requested_by_display: "someone",
    decided_by_user_id: null,
    decided_by_display: null,
    decision_note: null,
    result: null,
    error: null,
    expires_at: "2026-12-01T00:00:00Z",
    decided_at: null,
    executed_at: null,
    created_at: "2026-10-01T00:00:00Z",
    modified_at: "2026-10-01T00:00:00Z",
    can_approve: true,
    approve_blocked_reason: null,
  };
}

beforeEach(() => {
  listPage.mockClear();
});
afterEach(cleanup);

describe("admin change-request History paging", { timeout: 15000 }, () => {
  it("asks for decided states only, says how many are not shown, and loads more", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <ChangeRequestsPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByRole("button", { name: /history/i }));
    await screen.findByText("op-h0");
    const first = listPage.mock.calls.find((c) =>
      c[0].states?.includes("executed"),
    )![0];
    expect(first.states).not.toContain("pending");
    expect(first.offset).toBe(0);
    expect(screen.queryByText("op-h100")).toBeNull();
    await screen.findByText(/Showing the newest 100 of 150 decided requests/);

    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await screen.findByText("op-h149");
    expect(
      listPage.mock.calls.some(
        (c) => c[0].states?.includes("executed") && c[0].offset === 100,
      ),
    ).toBe(true);
    expect(screen.queryByText(/Showing the newest/)).toBeNull();
    expect(screen.getAllByText(/^op-h/)).toHaveLength(150);
  });
});
