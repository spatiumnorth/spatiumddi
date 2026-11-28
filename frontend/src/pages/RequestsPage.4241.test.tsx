/**
 * @vitest-environment jsdom
 *
 * Approve is disabled, with the server's reason, when the caller may not approve
 * a request (#4241) or its requester's account is gone (#4242).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
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
    can_approve: true,
    approve_blocked_reason: null,
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

const NOPERM = "Permission denied: need 'write' on 'dhcp_static'";
const GONE =
  "The requester's account no longer exists, so this request cannot be provisioned. Reject it; the requester can submit it again from a current account.";

function button(row: HTMLElement, name: string): HTMLButtonElement {
  return within(row).getByRole("button", { name }) as HTMLButtonElement;
}

describe("Approve follows the server's per-row can_approve (#4241, #4242)", () => {
  it("disables Approve with the reason; Reject and allowed rows stay live", async () => {
    listPage.mockResolvedValue({
      items: [
        req({
          id: "a",
          preview_text: "no op permission",
          can_approve: false,
          approve_blocked_reason: NOPERM,
        }),
        req({
          id: "b",
          preview_text: "requester gone",
          requested_by_user_id: null,
          can_approve: false,
          approve_blocked_reason: GONE,
        }),
        req({ id: "c", preview_text: "approvable" }),
      ],
      total: 3,
    });
    renderPage();
    const rowOf = async (t: string) =>
      (await screen.findByText(t)).closest("tr") as HTMLElement;
    const noperm = await rowOf("no op permission");
    const gone = await rowOf("requester gone");
    const ok = await rowOf("approvable");
    expect(button(noperm, "Approve").disabled).toBe(true);
    expect(button(noperm, "Approve").title).toBe(NOPERM);
    expect(button(noperm, "Reject").disabled).toBe(false);
    expect(button(gone, "Approve").disabled).toBe(true);
    expect(button(gone, "Approve").title).toBe(GONE);
    expect(button(gone, "Reject").disabled).toBe(false);
    expect(button(ok, "Approve").disabled).toBe(false);
  });
});
