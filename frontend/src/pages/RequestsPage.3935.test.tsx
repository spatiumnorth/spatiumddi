/**
 * @vitest-environment jsdom
 *
 * A decision refused with a 409 refreshes the list (#3935).
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

import type { ProvisioningRequest } from "@/lib/api";

const listPage = vi.fn();
const approve = vi.fn();
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
      approve: (...a: unknown[]) => approve(...a),
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
  for (const m of [listPage, approve, currentPreview]) m.mockReset();
});

describe("a decision refused with a 409 refreshes the list (#3935)", () => {
  it("shows the server's words and re-reads the queue", async () => {
    listPage.mockResolvedValue({ items: [req({})], total: 1 });
    currentPreview.mockResolvedValue({
      preview_text: "x",
      ok: true,
      detail: null,
      changed: false,
    });
    approve.mockRejectedValue({
      response: {
        status: 409,
        data: { detail: "This request was already cancelled by alice." },
      },
    });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await screen.findByRole("button", { name: "Approve and provision" });
    const before = listPage.mock.calls.length;
    fireEvent.click(
      screen.getByRole("button", { name: "Approve and provision" }),
    );
    expect(await screen.findByText(/already cancelled by alice/)).toBeTruthy();
    await waitFor(() =>
      expect(listPage.mock.calls.length).toBeGreaterThan(before),
    );
  });
});
