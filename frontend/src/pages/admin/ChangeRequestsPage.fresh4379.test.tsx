/**
 * @vitest-environment jsdom
 *
 * The approval-policy Edit dialog reads the policy when it opens and a Save
 * sends only what the operator changed (#4379).
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

const h = vi.hoisted(() => ({ reads: 0, update: vi.fn() }));

const base = {
  id: "ap1",
  name: "Delete subnets",
  resource_type: "subnet",
  action: "delete",
  min_count: null,
  enabled: true,
  applies_to_superadmin: true,
  ttl_hours: 168,
  is_builtin: false,
  created_at: "2026-10-01T00:00:00Z",
  modified_at: "2026-10-01T00:00:00Z",
};
// What another client stored after the list loaded.
const stored = { ...base, ttl_hours: 24, applies_to_superadmin: false };

function list() {
  h.reads += 1;
  return Promise.resolve([h.reads === 1 ? base : stored]);
}

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ id: "me" }) },
    changeRequestsApi: {
      ...actual.changeRequestsApi,
      list: async () => [],
      listPolicies: list,
      updatePolicy: (...a: unknown[]) => {
        h.update(...a);
        return Promise.resolve({ status: 200, data: stored });
      },
    },
    featureModulesApi: {
      ...actual.featureModulesApi,
      getApprovalsLock: async () => ({ approvals_protect_controls: false }),
    },
  };
});
vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ can: () => true, isSuperadmin: true }),
}));

const { ChangeRequestsPage } = await import("./ChangeRequestsPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  h.reads = 0;
});

async function openEdit() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <ChangeRequestsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(await screen.findByText("policies", {}, { timeout: 10000 }));
  fireEvent.click(
    await screen.findByRole("button", { name: /Edit/ }, { timeout: 10000 }),
  );
  return screen.findByDisplayValue("Delete subnets", {}, { timeout: 10000 });
}

describe(
  "Approval policy Edit reads the row and saves only the change",
  { timeout: 30000 },
  () => {
    it("shows the values stored since the list loaded", async () => {
      await openEdit();
      expect(
        await screen.findByDisplayValue("24", {}, { timeout: 10000 }),
      ).toBeTruthy();
    });

    it("an unrelated Save sends only that field", async () => {
      const name = await openEdit();
      fireEvent.change(name, { target: { value: "Renamed" } });
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(() => expect(h.update).toHaveBeenCalled(), {
        timeout: 10000,
      });
      expect(h.update).toHaveBeenCalledWith("ap1", { name: "Renamed" });
    });

    it("an untouched Save sends nothing", async () => {
      await openEdit();
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(
        () => expect(screen.queryByRole("button", { name: "Save" })).toBeNull(),
        { timeout: 10000 },
      );
      expect(h.update).not.toHaveBeenCalled();
    });
  },
);
