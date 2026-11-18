/**
 * @vitest-environment jsdom
 *
 * A linked customer the user may not read is said, never shown as "None" or
 * as a fragment of its id (#3527). A role with no read grant on customers is
 * refused GET /customers (403); a role that reads one other customer only
 * gets a list without this one (#3039). The edit forms keep the stored
 * customer selected as "(current customer)" and Save still sends it
 * unchanged. The multicast list's Customer cell says a customer is linked
 * without showing its id.
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

// The customer the user may not read. Its id's first 8 characters are what
// the multicast list showed in its place.
const HIDDEN = "c0ffee00-1111-4222-8333-444444444444";
const LIVE = { id: "c-live", name: "Live Co" };
const update = vi.fn(async () => ({}));

// How GET /auth/me/permissions answers, and so GET /customers; set per test.
let permMode: "no-customer-read" | "other-customer-only" = "no-customer-read";

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
  customer_id: HIDDEN,
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
  customer_id: HIDDEN,
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

const SERVICE = {
  id: "s1",
  name: "Branch WAN",
  kind: "custom",
  customer_id: HIDDEN,
  status: "active",
  sla_tier: null,
  term_start_date: null,
  term_end_date: null,
  monthly_cost_usd: null,
  currency: "USD",
  notes: "",
  tags: {},
  custom_fields: {},
  resources: [],
};

const OVERLAY = {
  id: "o1",
  name: "Branch mesh",
  kind: "sdwan",
  customer_id: HIDDEN,
  vendor: null,
  encryption_profile: null,
  default_path_strategy: "active_backup",
  status: "building",
  notes: "",
  site_count: 0,
  policy_count: 0,
};

// The ownership fields follow their feature modules (#4101); these tests are
// about the customer field itself, so every module is on.
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  // With no read grant on customers the route refuses; with a grant on one
  // customer it answers with that customer alone.
  const customersList = async () => {
    if (permMode === "no-customer-read")
      throw Object.assign(new Error("403"), { response: { status: 403 } });
    return { items: [LIVE], total: 1, limit: 500, offset: 0 };
  };
  const myPermissions = async () => ({
    is_superadmin: false,
    grants: [
      ...[
        "multicast_group",
        "circuit",
        "network_service",
        "overlay_network",
      ].map((resource_type) => ({
        action: "admin",
        resource_type,
        resource_id: null,
      })),
      ...(permMode === "other-customer-only"
        ? [{ action: "read", resource_type: "customer", resource_id: "c-live" }]
        : []),
    ],
  });
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
                        : name === "servicesApi" && method === "get"
                          ? async () => SERVICE
                          : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { CustomerPicker } = await import("@/components/ownership/pickers");
const { MulticastGroupModal, MulticastGroupsPage } =
  await import("./MulticastGroupsPage");
const { CircuitEditorModal } = await import("./CircuitsPage");
const { ServiceEditorModal } = await import("./ServicesPage");
const { OverlayEditorModal } = await import("./OverlaysPage");

beforeEach(() => {
  update.mockClear();
  permMode = "no-customer-read";
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

/** The select beside a form's "Customer" label. */
function customerField(label: string): HTMLSelectElement {
  const el = screen.getAllByText(label, { selector: "label" })[0];
  return el.parentElement!.querySelector("select") as HTMLSelectElement;
}

/** What the select shows: the text of its selected option. */
function shown(sel: HTMLSelectElement): string {
  return sel.selectedOptions[0]?.textContent ?? "";
}

async function settle() {
  // The refused list and the permissions have both answered by then.
  await new Promise((r) => setTimeout(r, 50));
}

const forms: [string, string, () => ReactNode][] = [
  [
    "multicast group",
    "Customer (optional)",
    () => (
      <MulticastGroupModal
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        existing={GROUP as any}
        spaces={[]}
        onClose={() => {}}
      />
    ),
  ],
  [
    "circuit",
    "Customer (optional)",
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    () => <CircuitEditorModal existing={CIRCUIT as any} onClose={() => {}} />,
  ],
  [
    "service",
    "Customer",
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    () => <ServiceEditorModal existing={SERVICE as any} onClose={() => {}} />,
  ],
  [
    "overlay",
    "Customer (optional)",
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    () => <OverlayEditorModal existing={OVERLAY as any} onClose={() => {}} />,
  ],
];

describe("a role refused the customer list (#3527)", () => {
  it.each(forms)(
    "the %s edit form shows the linked customer, not its placeholder",
    async (_kind, label, ui) => {
      wrap(ui());
      await settle();
      await waitFor(() =>
        expect(shown(customerField(label))).toBe("(current customer)"),
      );
      expect(customerField(label).value).toBe(HIDDEN);
    },
  );

  it("the shared picker (the subnet, IP space and block forms) shows it too", async () => {
    wrap(<CustomerPicker value={HIDDEN} onChange={() => {}} />);
    await settle();
    const sel = screen.getByRole("combobox") as HTMLSelectElement;
    await waitFor(() => expect(shown(sel)).toBe("(current customer)"));
    expect(sel.value).toBe(HIDDEN);
    expect(
      screen.queryByRole("option", { name: "(customer in Trash)" }),
    ).toBeNull();
  });

  it("a row with no customer still says None", async () => {
    wrap(<CustomerPicker value={null} onChange={() => {}} />);
    await settle();
    const sel = screen.getByRole("combobox") as HTMLSelectElement;
    expect(sel.value).toBe("");
    expect(
      screen.queryByRole("option", { name: "(current customer)" }),
    ).toBeNull();
  });

  it("Save on the multicast form still sends the customer unchanged", async () => {
    wrap(
      <MulticastGroupModal
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        existing={GROUP as any}
        spaces={[]}
        onClose={() => {}}
      />,
    );
    await settle();
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(update).toHaveBeenCalled());
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((update.mock.calls[0] as any)[1].customer_id).toBe(HIDDEN);
  });
});

describe("the multicast list's Customer cell (#3527)", () => {
  it.each(["no-customer-read", "other-customer-only"] as const)(
    "says the customer is linked, never a piece of its id (%s)",
    async (mode) => {
      permMode = mode;
      wrap(<MulticastGroupsPage />);
      await waitFor(() => expect(screen.getByText("239.1.1.1")).toBeTruthy());
      await settle();
      expect(screen.queryByText(HIDDEN.slice(0, 8))).toBeNull();
      await waitFor(() =>
        expect(screen.getByText("linked, not shown")).toBeTruthy(),
      );
      expect(screen.queryByText("(customer in Trash)")).toBeNull();
    },
  );
});
