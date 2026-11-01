/**
 * @vitest-environment jsdom
 *
 * A rejected request must tell the requester why (#2906).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import type { ProvisioningRequest } from "@/lib/api";

const rows = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ id: "u1" }) },
    requestsApi: {
      ...actual.requestsApi,
      list: () => rows(),
      catalog: async () => [],
    },
  };
});

vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ can: () => false, isSuperadmin: false }),
}));

import RequestsPage from "./RequestsPage";

function req(over: Partial<ProvisioningRequest>): ProvisioningRequest {
  return {
    id: "r1",
    operation: "create_subnet",
    resource_type: "subnet",
    resource_display: "10.9.0.0/24",
    args: {},
    preview_text: "Create subnet",
    justification: null,
    state: "rejected",
    requested_by_user_id: "u1",
    requested_by_display: "alice",
    decided_by_user_id: "u2",
    decided_by_display: "bob",
    decision_note: null,
    result: null,
    error: null,
    expires_at: "2026-12-01T00:00:00Z",
    decided_at: "2026-10-01T00:00:00Z",
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
  rows.mockReset();
});

describe("RequestsPage decision note (#2906)", () => {
  it("shows the reason on a rejected request", async () => {
    rows.mockResolvedValue([
      req({ decision_note: "Overlaps the lab range, pick another." }),
    ]);
    renderPage();
    expect(
      await screen.findByText(/Overlaps the lab range, pick another\./),
    ).toBeTruthy();
    expect(screen.getByTestId("decision-note")).toBeTruthy();
  });

  it("renders no empty note label when there is no note", async () => {
    rows.mockResolvedValue([req({ decision_note: null })]);
    renderPage();
    await screen.findByText("Create subnet");
    expect(screen.queryByTestId("decision-note")).toBeNull();
    expect(screen.queryByText("Note:")).toBeNull();
  });
});
