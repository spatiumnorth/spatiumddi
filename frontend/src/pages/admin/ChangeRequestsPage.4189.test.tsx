/**
 * @vitest-environment jsdom
 *
 * The queue disables Approve, with the server's reason, on a row the caller
 * may not approve (#4189) — e.g. a Change Approver without the operation's
 * own permission. Reject stays, since the server admits it.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import type { ChangeRequest } from "@/lib/api";

const REASON = "Permission denied: need 'delete' on 'subnet'";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ id: "me" }) },
    changeRequestsApi: {
      ...actual.changeRequestsApi,
      listPage: async () => ({
        items: [cr("blocked", false, REASON), cr("allowed", true, null)],
        total: 2,
      }),
    },
  };
});

vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ can: () => true, isSuperadmin: false }),
}));

import { ChangeRequestsPage } from "./ChangeRequestsPage";

function cr(
  id: string,
  can_approve: boolean,
  approve_blocked_reason: string | null,
): ChangeRequest {
  return {
    id,
    operation: `op-${id}`,
    resource_type: "subnet",
    resource_id: null,
    resource_display: id,
    args: {},
    preview_text: "p",
    risk_reason: "r",
    state: "pending",
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
    can_approve,
    approve_blocked_reason,
  };
}

function button(row: HTMLElement, label: string): HTMLButtonElement {
  const b = Array.from(row.querySelectorAll("button")).find((x) =>
    x.textContent?.includes(label),
  );
  if (!b) throw new Error(`no ${label} button`);
  return b as HTMLButtonElement;
}

afterEach(cleanup);

describe("change-request queue Approve gate", () => {
  it("disables Approve with the server's reason when can_approve is false", async () => {
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
    const blocked = (await screen.findByText("op-blocked")).closest("tr")!;
    const allowed = screen.getByText("op-allowed").closest("tr")!;
    await vi.waitFor(() => {
      expect(button(blocked, "Approve").disabled).toBe(true);
    });
    expect(button(blocked, "Approve").title).toBe(REASON);
    expect(button(blocked, "Reject").disabled).toBe(false);
    expect(button(allowed, "Approve").disabled).toBe(false);
  });
});
