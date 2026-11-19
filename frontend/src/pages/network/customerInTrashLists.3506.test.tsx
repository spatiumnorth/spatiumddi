/**
 * @vitest-environment jsdom
 *
 * Wherever something still names a customer in the Trash, the console says
 * so instead of showing None / nothing (#3506): the shared picker, the
 * multicast group and circuit edit forms, and the lists' customer chip. A
 * form holding the trashed id sends it back unchanged on Save. Only a list
 * that is every live customer can say so: a refused read (403), a truncated
 * list, or one narrowed to per-customer grants (#3039) never says "Trash".
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

const LIVE = { id: "c-live", name: "Live Co" };
const update = vi.fn(async () => ({}));

// How GET /customers and GET /auth/me/permissions answer; set per test.
let listMode: "complete" | "truncated" | "refused" = "complete";
let permMode: "superadmin" | "scoped" = "superadmin";

const GROUP = {
  id: "g1",
  space_id: "sp1",
  address: "239.1.1.1",
  name: "Cam 1",
  description: "",
  application: "",
  rtp_payload_type: null,
  bandwidth_mbps_estimate: null,
  vlan_id: null,
  customer_id: "c-gone",
  service_id: null,
  domain_id: null,
  tags: {},
  custom_fields: {},
};

const CIRCUIT = {
  id: "k1",
  name: "Ckt",
  ckt_id: "X1",
  provider_id: "p1",
  customer_id: "c-gone",
  transport_class: "internet_broadband",
  bandwidth_mbps_down: 1,
  bandwidth_mbps_up: 1,
  status: "active",
  a_end_site_id: null,
  a_end_subnet_id: null,
  z_end_site_id: null,
  z_end_subnet_id: null,
  term_start_date: null,
  term_end_date: null,
  monthly_cost: null,
  currency: "USD",
  notes: "",
};

// The ownership fields follow their feature modules (#4101); these tests are
// about the customer field itself, so every module is on.
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const customersList = async () => {
    if (listMode === "refused")
      throw Object.assign(new Error("403"), { response: { status: 403 } });
    return {
      items: [LIVE],
      total: listMode === "truncated" ? 600 : 1,
      limit: 500,
      offset: 0,
    };
  };
  // A scoped caller reads only the customer it is granted (#3039), so the
  // list it gets is complete for it and still lacks every other customer.
  const myPermissions = async () =>
    permMode === "superadmin"
      ? { is_superadmin: true, grants: [] }
      : {
          is_superadmin: false,
          grants: [
            {
              action: "read",
              resource_type: "customer",
              resource_id: "c-live",
            },
            {
              action: "*",
              resource_type: "multicast_group",
              resource_id: null,
            },
          ],
        };
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : name === "customersApi" && method === "list"
                  ? customersList
                  : name === "authApi" && method === "myPermissions"
                    ? myPermissions
                    : name === "multicastApi" && method === "update"
                      ? update
                      : name === "multicastApi" && method === "list"
                        ? async () => ({
                            items: [GROUP],
                            total: 1,
                            limit: 500,
                            offset: 0,
                          })
                        : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { CustomerPicker, CustomerChip } =
  await import("@/components/ownership/pickers");
const { MulticastGroupModal } = await import("./MulticastGroupsPage");
const { MulticastGroupsPage } = await import("./MulticastGroupsPage");
const { CircuitEditorModal } = await import("./CircuitsPage");

beforeEach(() => {
  update.mockClear();
  listMode = "complete";
  permMode = "superadmin";
});
afterEach(cleanup);

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function customerSelect(): HTMLSelectElement {
  const live = screen.getByRole("option", { name: LIVE.name });
  return live.closest("select") as HTMLSelectElement;
}

describe("a customer in the Trash is named as such (#3506)", () => {
  it("shared CustomerPicker keeps the trashed customer selected", async () => {
    wrap(<CustomerPicker value="c-gone" onChange={() => {}} />);
    await waitFor(() =>
      expect(
        screen.getByRole("option", { name: "(customer in Trash)" }),
      ).toBeTruthy(),
    );
    expect(customerSelect().value).toBe("c-gone");
  });

  it("CustomerChip says the customer is in the Trash", async () => {
    wrap(<CustomerChip customerId="c-gone" />);
    await waitFor(() =>
      expect(screen.getByText("(customer in Trash)")).toBeTruthy(),
    );
  });

  it("CustomerChip still names a live customer", async () => {
    wrap(<CustomerChip customerId="c-live" />);
    await waitFor(() => expect(screen.getByText("Live Co")).toBeTruthy());
    expect(screen.queryByText("(customer in Trash)")).toBeNull();
  });

  it("multicast edit form keeps the id and Save sends it unchanged", async () => {
    wrap(
      <MulticastGroupModal
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        existing={GROUP as any}
        spaces={[]}
        onClose={() => {}}
      />,
    );
    await waitFor(() =>
      expect(
        screen.getByRole("option", { name: "(customer in Trash)" }),
      ).toBeTruthy(),
    );
    expect(customerSelect().value).toBe("c-gone");
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(update).toHaveBeenCalled());
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((update.mock.calls[0] as any)[1].customer_id).toBe("c-gone");
  });

  it("circuit edit form keeps the trashed customer selected", async () => {
    wrap(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      <CircuitEditorModal existing={CIRCUIT as any} onClose={() => {}} />,
    );
    await waitFor(() =>
      expect(
        screen.getByRole("option", { name: "(customer in Trash)" }),
      ).toBeTruthy(),
    );
    expect(customerSelect().value).toBe("c-gone");
  });
});

describe("only a list of every live customer says Trash (#3506)", () => {
  async function settle() {
    // The list and the permissions have both answered once the live
    // customer's option or name is on screen.
    await new Promise((r) => setTimeout(r, 50));
  }

  it("a refused customers read (403) never says Trash", async () => {
    listMode = "refused";
    wrap(
      <>
        <CustomerChip customerId="c-gone" />
        <CustomerPicker value="c-gone" onChange={() => {}} />
      </>,
    );
    await settle();
    expect(screen.queryByText("(customer in Trash)")).toBeNull();
    expect(
      screen.queryByRole("option", { name: "(customer in Trash)" }),
    ).toBeNull();
  });

  it("a list narrowed to per-customer grants does not say Trash", async () => {
    permMode = "scoped";
    wrap(
      <>
        <CustomerChip customerId="c-gone" />
        <CustomerPicker value="c-gone" onChange={() => {}} />
      </>,
    );
    await waitFor(() =>
      expect(
        screen.getByRole("option", { name: "(current customer)" }),
      ).toBeTruthy(),
    );
    expect(customerSelect().value).toBe("c-gone");
    await settle();
    expect(screen.queryByText("(customer in Trash)")).toBeNull();
  });

  it("a truncated list's chip does not say Trash", async () => {
    listMode = "truncated";
    wrap(<CustomerChip customerId="c-gone" />);
    await settle();
    expect(screen.queryByText("(customer in Trash)")).toBeNull();
  });

  it("a picker with no customer offers no Trash option", async () => {
    wrap(<CustomerPicker value={null} onChange={() => {}} />);
    await waitFor(() => expect(customerSelect().value).toBe(""));
    expect(
      screen.queryByRole("option", { name: "(customer in Trash)" }),
    ).toBeNull();
    expect(
      screen.queryByRole("option", { name: "(current customer)" }),
    ).toBeNull();
  });

  it("the multicast list's cell says Trash, and only for every customer", async () => {
    wrap(<MulticastGroupsPage />);
    await waitFor(() =>
      expect(screen.getByText("(customer in Trash)")).toBeTruthy(),
    );
    expect(screen.queryByText("c-gone".slice(0, 8))).toBeNull();
    cleanup();
    permMode = "scoped";
    wrap(<MulticastGroupsPage />);
    await waitFor(() => expect(screen.getByText("239.1.1.1")).toBeTruthy());
    await settle();
    expect(screen.queryByText("(customer in Trash)")).toBeNull();
  });
});
