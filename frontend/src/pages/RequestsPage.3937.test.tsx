/**
 * @vitest-environment jsdom
 *
 * The Requests page pages its queue and says when it is cut (#3937).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import type { ProvisioningRequest } from "@/lib/api";

const listPage = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ id: "u9" }) },
    requestsApi: {
      ...actual.requestsApi,
      listPage: (...a: unknown[]) => listPage(...a),
      catalog: async () => [],
    },
  };
});

vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ can: () => true, isSuperadmin: false }),
}));

import RequestsPage from "./RequestsPage";

function req(over: Partial<ProvisioningRequest>): ProvisioningRequest {
  return {
    id: "r1",
    operation: "create_ip_address",
    resource_type: "ip_address",
    resource_display: "10.0.0.5",
    args: {},
    preview_text: "publishes A h.z1.test",
    justification: null,
    state: "pending",
    requested_by_user_id: "u1",
    requested_by_display: "alice",
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
    ...over,
  };
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <RequestsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  listPage.mockReset();
});

describe("the queue is paged and says when it is cut (#3937)", () => {
  it("offers the rest of the requests", async () => {
    listPage.mockImplementation(async (p: { offset?: number }) =>
      p.offset
        ? {
            items: [req({ id: "r101", preview_text: "oldest one" })],
            total: 101,
          }
        : {
            items: Array.from({ length: 100 }, (_, i) =>
              req({ id: `n${i}`, preview_text: `newer ${i}` }),
            ),
            total: 101,
          },
    );
    renderPage();
    expect(
      await screen.findByText(/Showing the newest 100 of 101/),
    ).toBeTruthy();
    expect(screen.queryByText("oldest one")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    expect(await screen.findByText("oldest one")).toBeTruthy();
    expect(screen.queryByText(/Showing the newest/)).toBeNull();
  });
});
