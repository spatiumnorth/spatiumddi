/**
 * @vitest-environment jsdom
 *
 * An Approve refused because the change's scope grew (#4381) leaves the row
 * without an enabled Approve and says what can be done: the approver rejects,
 * the requester cancels and submits again. Reject stays enabled.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import type { ChangeRequest } from "@/lib/api";

const DETAIL =
  "The change's scope changed since it was requested, so it can no longer be approved as reviewed. Reject it; the requester can cancel it and submit it again to capture the new scope.";

const approve = vi.fn(async () => {
  throw { response: { status: 409, data: { detail: DETAIL } } };
});

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ id: "me" }) },
    changeRequestsApi: {
      ...actual.changeRequestsApi,
      listPage: async () => ({ items: [cr("grown")], total: 1 }),
      approve: (...a: unknown[]) =>
        (approve as (...x: unknown[]) => unknown)(...a),
    },
  };
});

vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ can: () => true, isSuperadmin: false }),
}));

import { ChangeRequestsPage } from "./ChangeRequestsPage";

function cr(id: string): ChangeRequest {
  return {
    id,
    operation: `op-${id}`,
    resource_type: "dns_zone",
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
    can_approve: true,
    approve_blocked_reason: null,
  };
}

function button(root: HTMLElement, label: string): HTMLButtonElement {
  const b = Array.from(root.querySelectorAll("button")).find(
    (x) => x.textContent?.trim() === label,
  );
  if (!b) throw new Error(`no ${label} button`);
  return b as HTMLButtonElement;
}

afterEach(cleanup);

describe("scope-changed approve", { timeout: 15000 }, () => {
  it("turns Approve off with the reason and keeps Reject", async () => {
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
    const row = (await screen.findByText("op-grown")).closest("tr")!;
    expect(button(row, "Approve").disabled).toBe(false);
    fireEvent.click(button(row, "Approve"));
    await screen.findByText("Approve change request");
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(button(document.body, "Approve & execute"));
    await screen.findByText(DETAIL);
    fireEvent.click(button(document.body, "Cancel"));
    await vi.waitFor(() => {
      expect(button(row, "Approve").disabled).toBe(true);
    });
    expect(button(row, "Approve").title).toMatch(/Reject it/);
    expect(button(row, "Reject").disabled).toBe(false);
    expect(approve).toHaveBeenCalledTimes(1);
  });
});
