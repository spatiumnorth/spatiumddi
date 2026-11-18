/**
 * @vitest-environment jsdom
 *
 * A block's and a space's subnet selection offer Bulk Edit (n), Split… and
 * Merge… only to a holder the server would let through, as the subnet view
 * gates its own Split… and Merge… since #1155 (#3384). All three ask write on
 * subnets at the type level: `POST /subnets/bulk-edit` and the split and
 * merge commits at the router gate (`_IPAM_ROUTE_TYPES` in
 * `api/v1/ipam/router.py`), and every one of their handlers, the split and
 * merge previews included, through `_require_type_write(current_user,
 * "subnet")`. The built-in Viewer (read on everything) used to get all three
 * enabled, open the dialogs and meet a 403 in each.
 *
 * And when the server refuses a bulk edit, the dialog says the server's
 * reason, not the HTTP client's "Request failed with status code 403".
 * Real `usePermissions`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { IPBlock, IPSpace, Subnet } from "@/lib/api";

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

const block = {
  id: "blk-1",
  space_id: "sp-1",
  parent_block_id: null,
  network: "10.88.0.0/16",
  name: "lab-block",
  description: "",
  utilization_percent: 0,
  allocated_ips: 0,
  total_ips: 65536,
  dns_group_ids: [],
  custom_fields: {},
  tags: {},
} as unknown as IPBlock;

// Two adjacent /24s in the block, so one ticked offers Split… and both
// ticked offer Merge….
const subnet = (id: string, network: string) =>
  ({
    id,
    space_id: "sp-1",
    block_id: "blk-1",
    network,
    name: "",
    description: "",
    vlan_id: null,
    vxlan_id: null,
    gateway: null,
    status: "active",
    utilization_percent: 0,
    total_ips: 254,
    allocated_ips: 0,
    tags: {},
    custom_fields: {},
    dns_group_ids: null,
    dns_zone_id: null,
    dns_additional_zone_ids: null,
    dns_inherit_settings: true,
  }) as unknown as Subnet;

const FIRST = subnet("sn-1", "10.88.0.0/24");
const SECOND = subnet("sn-2", "10.88.1.0/24");

type G = [string, string, string | null];

/** The built-in Viewer role: read on everything. */
const VIEWER: G[] = [["read", "*", null]];

function signInAs(
  grants: G[] | "superadmin",
  ipam: Record<string, Answer> = {},
) {
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
    listBlocks: () => Promise.resolve([block]),
    getBlock: () => Promise.resolve(block),
    listSubnets: () => Promise.resolve([FIRST, SECOND]),
    ...ipam,
  };
}

// Let the permission set land: `can()` is false while it loads, so a
// disabled button proves nothing until then.
const settle = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 80));
  });

/** Open the view and tick the named subnet rows. */
async function tick(url: string, ...networks: string[]) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>
        <IPAMPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  for (const network of networks) {
    const box = await screen.findByRole(
      "checkbox",
      { name: `Select ${network}` },
      { timeout: 4000 },
    );
    fireEvent.click(box);
  }
  await settle();
}

const button = (name: string) =>
  screen.getByRole("button", { name }) as HTMLButtonElement;

const NEEDS_SUBNET_WRITE = "Requires write permission on subnets";

/** Each named button's state, so one assertion names every one offered. */
const gates = (...names: string[]) =>
  Object.fromEntries(
    names.map((name) => [
      name,
      { disabled: button(name).disabled, title: button(name).title },
    ]),
  );

const closed = (...names: string[]) =>
  Object.fromEntries(
    names.map((name) => [name, { disabled: true, title: NEEDS_SUBNET_WRITE }]),
  );

for (const [where, url] of [
  ["a block's", "/ipam?block=blk-1"],
  ["a space's", "/ipam?space=sp-1"],
] as const) {
  describe(`${where} subnet selection (#3384)`, () => {
    it("does not offer a Viewer Bulk Edit or Split… on one subnet: disabled, with the reason, and they open nothing", async () => {
      signInAs(VIEWER);
      await tick(url, FIRST.network);
      const names = ["Bulk Edit (1)", "Split…"];
      expect(gates(...names)).toEqual(closed(...names));
      for (const name of names) fireEvent.click(button(name));
      await settle();
      expect(screen.queryByRole("dialog")).toBeNull();
    });

    it("does not offer a Viewer Bulk Edit or Merge… on two subnets", async () => {
      signInAs(VIEWER);
      await tick(url, FIRST.network, SECOND.network);
      const names = ["Bulk Edit (2)", "Merge…"];
      expect(gates(...names)).toEqual(closed(...names));
      for (const name of names) fireEvent.click(button(name));
      await settle();
      expect(screen.queryByRole("dialog")).toBeNull();
    });

    it("keeps them disabled for a write grant scoped to the ticked subnet (the server asks at the type level)", async () => {
      signInAs([...VIEWER, ["write", "subnet", FIRST.id]]);
      await tick(url, FIRST.network);
      const names = ["Bulk Edit (1)", "Split…"];
      expect(gates(...names)).toEqual(closed(...names));
    });

    it("offers them to a holder with write on subnets, and each opens its dialog", async () => {
      signInAs([...VIEWER, ["write", "subnet", null]]);
      await tick(url, FIRST.network);
      expect(button("Bulk Edit (1)").disabled).toBe(false);
      expect(button("Split…").disabled).toBe(false);
      fireEvent.click(button("Split…"));
      expect((await screen.findByRole("dialog")).textContent ?? "").toContain(
        `Split subnet ${FIRST.network}`,
      );
    });

    it("offers Merge… to a holder with write on subnets, and it opens its dialog", async () => {
      signInAs([...VIEWER, ["write", "subnet", null]]);
      await tick(url, FIRST.network, SECOND.network);
      expect(button("Bulk Edit (2)").disabled).toBe(false);
      fireEvent.click(button("Merge…"));
      expect((await screen.findByRole("dialog")).textContent ?? "").toContain(
        "Merge subnet",
      );
    });

    it("offers them to a superadmin", async () => {
      signInAs("superadmin");
      await tick(url, FIRST.network, SECOND.network);
      expect(button("Bulk Edit (2)").disabled).toBe(false);
      expect(button("Merge…").disabled).toBe(false);
    });
  });
}

const REASON = "Permission denied: need 'write' on each of ['subnet']";

// What axios hands the caller for a refused request: its own message, and
// the server's answer under `response`.
const refused = () =>
  Promise.reject(
    Object.assign(new Error("Request failed with status code 403"), {
      response: { status: 403, data: { detail: REASON } },
    }),
  );

/** As a holder of write on subnets, open Bulk Edit on the block's first
 *  subnet, fill in what `fill` sets, and press Apply. */
async function applyBulkEdit(
  bulkEditSubnets: Answer,
  fill: (dialog: HTMLElement) => void,
) {
  signInAs([...VIEWER, ["write", "subnet", null]], { bulkEditSubnets });
  await tick("/ipam?block=blk-1", FIRST.network);
  fireEvent.click(button("Bulk Edit (1)"));
  const dialog = await screen.findByRole("dialog");
  expect(dialog.textContent ?? "").toContain("Bulk edit 1 subnet");
  fill(dialog);
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
  });
  await settle();
  return dialog;
}

describe("the Bulk edit subnets dialog (#3384)", () => {
  it("says the server's reason when the server refuses the edit", async () => {
    const calls: unknown[][] = [];
    const dialog = await applyBulkEdit(
      (...args) => {
        calls.push(args);
        return refused();
      },
      () =>
        fireEvent.change(screen.getByLabelText("Description"), {
          target: { value: "edge uplinks" },
        }),
    );
    expect(calls).toEqual([[[FIRST.id], { description: "edge uplinks" }]]);
    expect(dialog.textContent ?? "").not.toContain(
      "Request failed with status code",
    );
    expect(screen.getByText(REASON)).toBeTruthy();
  });

  it("keeps its own messages word for word", async () => {
    let called = false;
    await applyBulkEdit(
      () => {
        called = true;
        return Promise.resolve({ batch_id: "b-1", updated_count: 1 });
      },
      () => {},
    );
    expect(called).toBe(false);
    expect(screen.getByText("Set at least one field to apply")).toBeTruthy();
  });
});

// #3884: the selection's Delete (n) asks delete on subnets, as the delete
// handler does before the approval gate.
for (const [where, url] of [
  ["a block's", "/ipam?block=blk-1"],
  ["a space's", "/ipam?space=sp-1"],
] as const) {
  describe(`${where} subnet selection Delete (#3884)`, () => {
    it("does not offer a Viewer Delete (n): disabled, with the reason, and it opens nothing", async () => {
      signInAs(VIEWER);
      await tick(url, FIRST.network);
      expect(gates("Delete (1)")).toEqual({
        "Delete (1)": {
          disabled: true,
          title: "Requires delete permission on subnets",
        },
      });
      fireEvent.click(button("Delete (1)"));
      await settle();
      expect(screen.queryByRole("dialog")).toBeNull();
    });

    it("offers it to a holder with delete on subnets", async () => {
      signInAs([...VIEWER, ["delete", "subnet", null]]);
      await tick(url, FIRST.network);
      expect(button("Delete (1)").disabled).toBe(false);
      fireEvent.click(button("Delete (1)"));
      expect(await screen.findByRole("dialog")).toBeTruthy();
    });

    it("offers it to a superadmin", async () => {
      signInAs("superadmin");
      await tick(url, FIRST.network);
      expect(button("Delete (1)").disabled).toBe(false);
    });
  });
}
