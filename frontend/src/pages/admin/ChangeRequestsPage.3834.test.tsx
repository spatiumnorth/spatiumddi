/**
 * @vitest-environment jsdom
 *
 * The admin queue offers no Approve / Reject on the viewer's own request
 * (#3834), and its decision note stops at the server's 2000 characters (#3835).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import type { ChangeRequest } from "@/lib/api";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ id: "me" }) },
    changeRequestsApi: {
      ...actual.changeRequestsApi,
      list: async () => [cr("own", "me"), cr("other", "someone")],
    },
  };
});

vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ can: () => true, isSuperadmin: false }),
}));

import { ChangeRequestsPage } from "./ChangeRequestsPage";

function cr(id: string, by: string): ChangeRequest {
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
    requested_by_user_id: by,
    requested_by_display: by,
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
  };
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ChangeRequestsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(cleanup);

describe("admin change-request queue", () => {
  it("offers no Approve or Reject on the viewer's own request", async () => {
    renderPage();
    const own = (await screen.findByText("op-own")).closest("tr")!;
    const other = screen.getByText("op-other").closest("tr")!;
    // The other row is offered both once permissions + /auth/me have loaded.
    await vi.waitFor(() => {
      expect(other.textContent).toContain("Approve");
      expect(other.textContent).toContain("Reject");
      expect(own.textContent).not.toContain("Approve");
    });
    expect(own.textContent).not.toContain("Reject");
    expect(own.textContent).toContain("Cancel");
  });

  it("limits the decision note to the server's 2000 characters", async () => {
    renderPage();
    const other = (await screen.findByText("op-other")).closest("tr")!;
    await userEvent.click(
      await vi.waitFor(() => {
        const b = Array.from(other.querySelectorAll("button")).find((x) =>
          x.textContent?.includes("Approve"),
        );
        if (!b) throw new Error("no approve yet");
        return b;
      }),
    );
    const box = (await screen.findAllByRole("textbox"))[0];
    expect(box.getAttribute("maxlength")).toBe("2000");
  });
});
