/**
 * @vitest-environment jsdom
 *
 * #3466: the VRFs page for a user whose role reads and writes VRFs and
 * nothing else. The ASN column asked GET /asns (read on `manage_asns`) for
 * each VRF linked to an ASN and, refused, showed an ellipsis titled with the
 * ASN's raw id. The row's customer chip and Edit VRF's Customer picker asked
 * GET /customers (read on `customer`) and, refused, the picker showed "None"
 * over the VRF's linked customer. Each refusal is a 403 and a denied audit
 * row, every time. Neither list is asked now without its grant, and the page
 * says the link is there but not shown.
 *
 * Every API call stays pending unless a test answers it.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

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
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { VRFsPage } = await import("./VRFsPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

type G = [string, string, string | null];

function signInAs(grants: G[]) {
  answer("authApi", "myPermissions", () =>
    Promise.resolve({
      is_superadmin: false,
      grants: grants.map(([action, resource_type, resource_id]) => ({
        action,
        resource_type,
        resource_id,
      })),
    }),
  );
}

/** A role granting read and write on VRFs, and nothing else. */
const VRF_ONLY: G[] = [
  ["read", "vrf", null],
  ["write", "vrf", null],
];

function refusal(on: string) {
  return Object.assign(new Error("Request failed with status code 403"), {
    isAxiosError: true,
    status: 403,
    response: {
      status: 403,
      data: { detail: `Permission denied: need 'read' on '${on}'` },
    },
  });
}

const STAMP = "2026-11-04T00:00:00Z";
const VRF = {
  id: "vrf-1",
  name: "CUST-A",
  description: "old",
  asn_id: "asn-1",
  route_distinguisher: "65010:1",
  import_targets: [],
  export_targets: [],
  tags: {},
  custom_fields: {},
  customer_id: "cust-1",
  created_at: STAMP,
  modified_at: STAMP,
  space_count: 0,
  block_count: 0,
};

/** Answers the page's own list, and spies on the two lists it may not ask. */
function lists(asns: Answer, customers: Answer) {
  answer("vrfsApi", "list", () => Promise.resolve([VRF]));
  const asnList = vi.fn(asns);
  const customerList = vi.fn(customers);
  answer("asnsApi", "list", asnList);
  answer("customersApi", "list", customerList);
  return { asnList, customerList };
}

async function showPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <VRFsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const row = (await screen.findByText("CUST-A")).closest("tr")!;
  // Let the permission set and every cell's own read answer.
  await act(async () => {
    await new Promise((r) => setTimeout(r, 80));
  });
  return row;
}

describe("VRFs page reads for a user who may not read ASNs or customers (#3466)", () => {
  it("the ASN column asks no ASN list and says the linked ASN is not shown", async () => {
    signInAs(VRF_ONLY);
    const { asnList, customerList } = lists(
      () => Promise.reject(refusal("manage_asns")),
      () => Promise.reject(refusal("customer")),
    );
    const row = await showPage();
    const cell = within(row).getByText("linked, not shown");
    expect(cell.getAttribute("title")).toMatch(/may not read/);
    expect(within(row).queryByText("…")).toBeNull();
    expect(row.innerHTML).not.toContain('title="asn-1"');
    expect(asnList).not.toHaveBeenCalled();
    // The row's customer chip is not asked either.
    expect(customerList).not.toHaveBeenCalled();
  });

  it("Edit VRF's Customer picker asks no customer list, says the link is there, and Save keeps both links", async () => {
    signInAs(VRF_ONLY);
    const { asnList, customerList } = lists(
      () => Promise.reject(refusal("manage_asns")),
      () => Promise.reject(refusal("customer")),
    );
    const update = vi.fn((..._a: unknown[]) => Promise.resolve(VRF));
    answer("vrfsApi", "update", update);
    const row = await showPage();
    fireEvent.click(within(row).getByRole("button", { name: "Edit VRF" }));
    const picker = (await screen.findByTitle(
      /cannot read customers/,
    )) as HTMLSelectElement;
    expect(picker.disabled).toBe(true);
    expect(picker.selectedOptions[0].textContent).toBe(
      "Linked (not visible to your role)",
    );
    fireEvent.change(screen.getByDisplayValue("old"), {
      target: { value: "new" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update.mock.calls[0][1]).toMatchObject({
      description: "new",
      asn_id: "asn-1",
      customer_id: "cust-1",
    });
    expect(asnList).not.toHaveBeenCalled();
    expect(customerList).not.toHaveBeenCalled();
  });

  it("a VRF with no customer shows None in the picker, still disabled with the reason", async () => {
    signInAs(VRF_ONLY);
    const { customerList } = lists(
      () => Promise.reject(refusal("manage_asns")),
      () => Promise.reject(refusal("customer")),
    );
    answer("vrfsApi", "list", () =>
      Promise.resolve([{ ...VRF, customer_id: null }]),
    );
    const row = await showPage();
    fireEvent.click(within(row).getByRole("button", { name: "Edit VRF" }));
    const picker = (await screen.findByTitle(
      /cannot read customers/,
    )) as HTMLSelectElement;
    expect(picker.disabled).toBe(true);
    expect(picker.selectedOptions[0].textContent).toBe("\u2014 None \u2014");
    expect(customerList).not.toHaveBeenCalled();
  });

  it("still asks both lists, and names the ASN and the customer, for a user who may read them", async () => {
    signInAs([
      ...VRF_ONLY,
      ["read", "manage_asns", null],
      ["read", "customer", null],
    ]);
    const { asnList, customerList } = lists(
      () =>
        Promise.resolve({
          items: [
            { id: "asn-1", number: 65010, name: "edge", kind: "private" },
          ],
          total: 1,
        }),
      () =>
        Promise.resolve({
          items: [{ id: "cust-1", name: "Acme", account_number: null }],
          total: 1,
          limit: 500,
          offset: 0,
        }),
    );
    const row = await showPage();
    expect(
      await within(row).findByRole("link", { name: /AS65010/ }),
    ).toBeTruthy();
    expect(await within(row).findByText("Acme")).toBeTruthy();
    fireEvent.click(within(row).getByRole("button", { name: "Edit VRF" }));
    await waitFor(() =>
      expect(
        screen
          .getAllByRole("option", { name: "Acme" })
          .some((o) => (o as HTMLOptionElement).selected),
      ).toBe(true),
    );
    expect(asnList).toHaveBeenCalled();
    expect(customerList).toHaveBeenCalled();
  });

  it("asks the customer list of a user whose customer read is scoped to one customer (the API narrows it)", async () => {
    signInAs([...VRF_ONLY, ["read", "customer", "cust-9"]]);
    const { customerList } = lists(
      () => Promise.reject(refusal("manage_asns")),
      () =>
        Promise.resolve({
          items: [{ id: "cust-9", name: "Own", account_number: null }],
          total: 1,
          limit: 500,
          offset: 0,
        }),
    );
    const row = await showPage();
    fireEvent.click(within(row).getByRole("button", { name: "Edit VRF" }));
    expect(await screen.findByRole("option", { name: "Own" })).toBeTruthy();
    expect(customerList).toHaveBeenCalled();
  });
});
