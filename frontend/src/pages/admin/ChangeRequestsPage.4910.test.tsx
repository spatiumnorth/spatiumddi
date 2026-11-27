/**
 * @vitest-environment jsdom
 *
 * The approval-policy dialog offers only what the server gates (#4910) and
 * refuses a TTL the server would refuse instead of saving 168 (#4911).
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

const h = vi.hoisted(() => ({ create: vi.fn() }));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ id: "me" }) },
    changeRequestsApi: {
      ...actual.changeRequestsApi,
      list: async () => [],
      listPolicies: async () => [],
      gateablePairs: async () => [
        { action: "admin", resource_type: "manage_block_sync" },
        { action: "delete", resource_type: "subnet" },
      ],
      createPolicy: (...a: unknown[]) => {
        h.create(...a);
        return Promise.resolve({});
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
});

async function openNew() {
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
    await screen.findByRole(
      "button",
      { name: /New policy/ },
      { timeout: 10000 },
    ),
  );
  await screen.findByText("New approval policy", {}, { timeout: 10000 });
}

describe("Approval policy dialog", { timeout: 30000 }, () => {
  it("offers only the actions the server gates", async () => {
    await openNew();
    await waitFor(
      () => {
        const opts = Array.from(
          (screen.getByLabelText("Action") as HTMLSelectElement).options,
        ).map((o) => o.value);
        expect(opts).toEqual(["admin", "delete"]);
      },
      { timeout: 10000 },
    );
  });

  it("refuses a TTL of 0 or blank without saving 168", async () => {
    await openNew();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText("Resource type"), {
      target: { value: "subnet" },
    });
    for (const v of ["0", ""]) {
      fireEvent.change(screen.getByLabelText("TTL (hours)"), {
        target: { value: v },
      });
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
      expect(
        await screen.findByText(/TTL must be a whole number/),
      ).toBeTruthy();
    }
    expect(h.create).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("TTL (hours)"), {
      target: { value: "24" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(h.create).toHaveBeenCalled());
    expect(h.create.mock.calls[0][0].ttl_hours).toBe(24);
  });
});
