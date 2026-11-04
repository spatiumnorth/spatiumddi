/**
 * @vitest-environment jsdom
 *
 * The address search ("Find IP addresses across all subnets", #520) offers
 * Bulk edit only to a holder the server would let through, as the Delete
 * beside it already is (#1155's pattern: visible, disabled, with the reason)
 * (#3423).
 *
 * What `POST /ipam/addresses/bulk-edit` asks at the router gate
 * (`_IPAM_GATE`, `require_any_resource_or_scoped` in `core/permissions.py`):
 * write on subnets at the type level (`_IPAM_ROUTE_TYPES`), or, for an
 * address-set delegate (#103), any write grant on an address set, whatever
 * set it names (the route is on `_ADDRESS_SET_ROUTES`, admitted through
 * `has_any_grant_for`). Anyone else is refused with 403 "Permission denied:
 * need 'write' on each of ['subnet']", a grant scoped to one subnet
 * included. The handler then skips each address the caller cannot write
 * (its subnet, or a covering address set).
 *
 * The built-in Viewer (read on everything) used to get Bulk edit enabled
 * on any match it ticked, and meet that 403 on Apply. Real `usePermissions`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { IPAddressSearchItem, IPSpace } from "@/lib/api";

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

const { IPAMPage } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
  sessionStorage.clear();
});

const space = {
  id: "sp-1",
  name: "lab-space",
  description: "",
  custom_fields: {},
  tags: {},
} as unknown as IPSpace;

// One match, in a subnet the caller can read.
const MATCH = {
  id: "ip-1",
  subnet_id: "sn-1",
  address: "10.88.0.10",
  status: "allocated",
  hostname: "db01",
  fqdn: "db01.lab.example",
  mac_address: null,
  description: "",
  tags: {},
  custom_fields: {},
  auto_from_lease: false,
  subnet_cidr: "10.88.0.0/24",
  subnet_name: "lab",
  space_id: "sp-1",
  space_name: "lab-space",
} as unknown as IPAddressSearchItem;

type G = [string, string, string | null];

/** The built-in Viewer role: read on everything. */
const VIEWER: G[] = [["read", "*", null]];

function signInAs(grants: G[] | "superadmin") {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve(
        grants === "superadmin"
          ? { is_superadmin: true, grants: [] }
          : {
              is_superadmin: false,
              grants: grants.map(([action, resource_type, resource_id]) => ({
                action,
                resource_type,
                resource_id,
              })),
            },
      ),
  };
  answers.ipamApi = {
    listSpaces: () => Promise.resolve([space]),
    getSpace: () => Promise.resolve(space),
    listBlocks: () => Promise.resolve([]),
    listSubnets: () => Promise.resolve([]),
    searchAddresses: () =>
      Promise.resolve({ items: [MATCH], total: 1, limit: 100, offset: 0 }),
  };
}

// Let the permission set land: `can()` is false while it loads, so a
// disabled button proves nothing until then.
const settle = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 80));
  });

/** Open the address search, find the match and tick it. */
async function searchAndTick() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/ipam"]}>
        <IPAMPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(
    await screen.findByRole(
      "button",
      { name: "Find IP addresses across all subnets" },
      { timeout: 4000 },
    ),
  );
  const dialog = await screen.findByRole("dialog", {
    name: /Find IP addresses/,
  });
  fireEvent.change(within(dialog).getByRole("textbox"), {
    target: { value: "10.88.0" },
  });
  fireEvent.click(within(dialog).getByRole("button", { name: "Search" }));
  fireEvent.click(
    await within(dialog).findByRole("checkbox", {}, { timeout: 4000 }),
  );
  await settle();
  return dialog;
}

const NEEDS_ADDRESS_WRITE =
  "Requires write permission on this subnet or on an address set in it";
const NEEDS_ADDRESS_DELETE =
  "Requires delete permission on subnets, and write on this subnet or on an address set in it";

const bulkEdit = (dialog: HTMLElement) =>
  within(dialog).getByRole("button", {
    name: /^Bulk edit/,
  }) as HTMLButtonElement;

const deleteButton = (dialog: HTMLElement) =>
  within(dialog).getByRole("button", {
    name: /^Delete/,
  }) as HTMLButtonElement;

/** The footer's two writes on the ticked match, so one assertion names
 *  both: enabled or not, and the reason a disabled one gives (its tooltip). */
function footer(dialog: HTMLElement) {
  const state = (b: HTMLButtonElement) => ({
    disabled: b.disabled,
    title: b.title,
  });
  return {
    "Delete 1…": state(deleteButton(dialog)),
    "Bulk edit 1…": state(bulkEdit(dialog)),
  };
}

const bulkEditDialog = () =>
  screen.queryByRole("dialog", { name: "Bulk edit 1 IP addresses" });

describe("the address search's Bulk edit (#3423)", () => {
  it("is not offered to a Viewer, as Delete is not: disabled, with the reason, and it opens nothing", async () => {
    signInAs(VIEWER);
    const dialog = await searchAndTick();
    expect(footer(dialog)).toEqual({
      "Delete 1…": { disabled: true, title: NEEDS_ADDRESS_DELETE },
      "Bulk edit 1…": { disabled: true, title: NEEDS_ADDRESS_WRITE },
    });
    fireEvent.click(bulkEdit(dialog));
    await settle();
    expect(bulkEditDialog()).toBeNull();
  });

  it("stays disabled for a write grant scoped to the match's subnet (the route asks write on subnets at the type level)", async () => {
    signInAs([...VIEWER, ["write", "subnet", MATCH.subnet_id]]);
    const dialog = await searchAndTick();
    expect(footer(dialog)["Bulk edit 1…"]).toEqual({
      disabled: true,
      title: NEEDS_ADDRESS_WRITE,
    });
  });

  it("is offered to a holder of write on subnets, and it opens its dialog", async () => {
    signInAs([...VIEWER, ["write", "subnet", null]]);
    const dialog = await searchAndTick();
    expect(footer(dialog)["Bulk edit 1…"]).toEqual({
      disabled: false,
      title: "",
    });
    fireEvent.click(bulkEdit(dialog));
    expect(
      await screen.findByRole("dialog", { name: "Bulk edit 1 IP addresses" }),
    ).toBeTruthy();
  });

  it.each([
    ["a write grant on one address set", ["write", "address_set", "as-1"]],
    [
      "the Address Set Editor's admin on one address set",
      ["admin", "address_set", "as-1"],
    ],
  ] as [string, G][])(
    "is offered to an address-set delegate, whom the route admits (#103): %s",
    async (_label, grant) => {
      signInAs([...VIEWER, grant]);
      const dialog = await searchAndTick();
      expect(footer(dialog)["Bulk edit 1…"]).toEqual({
        disabled: false,
        title: "",
      });
      fireEvent.click(bulkEdit(dialog));
      expect(
        await screen.findByRole("dialog", { name: "Bulk edit 1 IP addresses" }),
      ).toBeTruthy();
    },
  );

  it("is offered to a superadmin", async () => {
    signInAs("superadmin");
    const dialog = await searchAndTick();
    expect(footer(dialog)["Bulk edit 1…"]).toEqual({
      disabled: false,
      title: "",
    });
  });
});
