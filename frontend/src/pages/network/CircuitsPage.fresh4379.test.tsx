/**
 * @vitest-environment jsdom
 *
 * The circuit Edit dialog reads the circuit when it opens and a Save sends
 * only what the operator changed (#4379). Before, it seeded from the
 * click-time list row and PUT every field, so a value another client stored
 * since the list loaded was put back by an unrelated Save.
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

const h = vi.hoisted(() => ({ update: vi.fn() }));

const BASE = {
  id: "c1",
  name: "NYC-LON old",
  ckt_id: "CKT-1",
  provider_id: "p1",
  customer_id: null,
  transport_class: "internet_broadband",
  bandwidth_mbps_down: 100,
  bandwidth_mbps_up: 100,
  a_end_site_id: null,
  a_end_subnet_id: null,
  z_end_site_id: null,
  z_end_subnet_id: null,
  term_start_date: null,
  term_end_date: null,
  monthly_cost: null,
  currency: "USD",
  status: "active",
  notes: "",
  tags: {},
  custom_fields: {},
  previous_status: null,
  last_status_change_at: null,
  created_at: "",
  modified_at: "",
};
const FRESH = { ...BASE, name: "changed elsewhere", ckt_id: "CKT-NEW" };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    circuitsApi: {
      ...actual.circuitsApi,
      // The list holds the stale row; the dialog reads the row itself.
      list: () =>
        Promise.resolve({ items: [BASE], total: 1, limit: 500, offset: 0 }),
      get: () => Promise.resolve(FRESH),
      update: (...a: unknown[]) => {
        h.update(...a);
        return Promise.resolve(FRESH);
      },
    },
    providersApi: {
      ...actual.providersApi,
      list: () =>
        Promise.resolve({
          items: [{ id: "p1", name: "prov", kind: "carrier" }],
          total: 1,
          limit: 500,
          offset: 0,
        }),
    },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => false }),
}));
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

const { CircuitsPage } = await import("./CircuitsPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

async function openEdit() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <CircuitsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const btn = await screen.findByTitle("Edit", {}, { timeout: 10000 });
  fireEvent.click(btn);
  return (await screen.findByDisplayValue(
    "changed elsewhere",
    {},
    { timeout: 10000 },
  )) as HTMLInputElement;
}

describe("circuit Edit dialog (#4379)", { timeout: 30000 }, () => {
  it("shows what is stored now, not the click-time list row", async () => {
    const name = await openEdit();
    expect(name.value).toBe("changed elsewhere");
    expect(screen.getByDisplayValue("CKT-NEW")).toBeTruthy();
  });

  it("an unrelated change sends only that field", async () => {
    const name = await openEdit();
    fireEvent.change(name, { target: { value: "renamed" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(h.update).toHaveBeenCalledTimes(1), {
      timeout: 10000,
    });
    expect(h.update).toHaveBeenCalledWith("c1", { name: "renamed" });
  });

  it("a Save with nothing changed sends nothing", async () => {
    await openEdit();
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(
      () => expect(screen.queryByDisplayValue("changed elsewhere")).toBeNull(),
      { timeout: 10000 },
    );
    expect(h.update).not.toHaveBeenCalled();
  });
});
