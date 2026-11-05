/**
 * @vitest-environment jsdom
 *
 * Wherever something still names a customer in the Trash, the console says
 * so instead of showing None / nothing (#3506): the shared picker, the
 * multicast group and circuit edit forms, and the lists' customer chip. A
 * form holding the trashed id sends it back unchanged on Save.
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

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
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
                  ? async () => ({
                      items: [LIVE],
                      total: 1,
                      limit: 500,
                      offset: 0,
                    })
                  : name === "multicastApi" && method === "update"
                    ? update
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
const { CircuitEditorModal } = await import("./CircuitsPage");

beforeEach(() => update.mockClear());
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
