/**
 * @vitest-environment jsdom
 *
 * The Approve dialog shows what approving does now (#3934).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import type { ProvisioningRequest } from "@/lib/api";

const listPage = vi.fn();
const currentPreview = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ id: "u9" }) },
    requestsApi: {
      ...actual.requestsApi,
      listPage: (...a: unknown[]) => listPage(...a),
      catalog: async () => [],
      currentPreview: (...a: unknown[]) => currentPreview(...a),
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
  for (const m of [listPage, currentPreview]) m.mockReset();
});

describe("the Approve dialog shows what approving does now (#3934)", () => {
  it("shows the re-previewed text and says the request changed", async () => {
    listPage.mockResolvedValue({ items: [req({})], total: 1 });
    currentPreview.mockResolvedValue({
      preview_text: "publishes A h.z2.test",
      ok: true,
      detail: null,
      changed: true,
    });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    expect(
      await screen.findByText(/changed since it was submitted/),
    ).toBeTruthy();
    expect(
      screen.getAllByText(/publishes A h\.z2\.test/).length,
    ).toBeGreaterThan(0);
  });

  it("warns when the request can no longer be provisioned", async () => {
    listPage.mockResolvedValue({ items: [req({})], total: 1 });
    currentPreview.mockResolvedValue({
      preview_text: "publishes A h.z1.test",
      ok: false,
      detail: "Subnet not found.",
      changed: false,
    });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    expect(
      await screen.findByText(/can no longer be provisioned/),
    ).toBeTruthy();
  });
});
