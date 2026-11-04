/**
 * @vitest-environment jsdom
 *
 * A read-only user is offered no write on the IPAM tree's right-click menus,
 * drag-to-move, Find Free's "Create subnet here" or a free band segment
 * (#3391, #3392), the rest of what #1175 / #2520 gated.
 */

import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
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
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: () => true,
  }),
}));

const { SpaceSection, BlockDetailView, SubnetDetail } =
  await import("./IPAMPage");

vi.setConfig({ testTimeout: 30_000 });

// What Radix's menu needs from jsdom (as components/ui/context-menu.test.tsx).
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver;
Element.prototype.scrollIntoView ??= () => {};
const realMatches = Element.prototype.matches;
beforeAll(() => {
  Element.prototype.matches = function (sel: string) {
    if (sel === ":popover-open" || sel === ":modal") return false;
    return realMatches.call(this, sel);
  };
});
afterAll(() => {
  Element.prototype.matches = realMatches;
});

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-11-03T00:00:00Z";

type Grant = [string, string] | [string, string, string];
function signInAs(grants: Grant[] | "superadmin") {
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
                resource_id: resource_id ?? null,
              })),
            },
      ),
  };
}
const VIEWER: [string, string][] = [["read", "*"]];

const settle = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });

const space = { id: "sp-1", name: "lab" } as unknown as IPSpace;
const block = {
  id: "blk-1",
  space_id: "sp-1",
  parent_block_id: null,
  network: "10.142.0.0/16",
  name: "",
  created_at: STAMP,
  utilization_percent: 0,
  total_ips: 0,
  allocated_ips: 0,
  tags: {},
  custom_fields: {},
  customer_id: null,
  site_id: null,
} as unknown as IPBlock;
const subnet = {
  id: "sub-1",
  space_id: "sp-1",
  block_id: "blk-1",
  network: "10.142.1.0/24",
  name: "sn1",
  total_ips: 254,
  allocated_ips: 1,
  utilization_percent: 1,
  dns_group_ids: [],
  customer_id: null,
  site_id: null,
} as unknown as Subnet;

const wrap = (ui: React.ReactNode) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
};

// Role queries walk the whole accessibility tree, which is slow in jsdom;
// these tests read the DOM by attribute instead.
const q = (sel: string) => document.querySelector(sel) as HTMLElement | null;
const treeitem = (name: string) =>
  q(`[role="treeitem"][aria-label="${name}"]`) as HTMLElement;
const headings = () =>
  Array.from(document.querySelectorAll("h2")).map((h) => h.textContent);

async function openTree(
  onSelectSubnet: (s: Subnet | null) => void = () => {},
  onSelectBlock: (b: IPBlock) => void = () => {},
) {
  answers.ipamApi = {
    listSubnets: () => Promise.resolve([subnet]),
    listBlocks: () => Promise.resolve([block]),
    getSubnet: () => Promise.resolve(subnet),
  };
  wrap(
    <SpaceSection
      space={space}
      selectedSubnetId={null}
      selectedBlockId={null}
      isSpaceSelected={false}
      onSelectSpace={() => {}}
      onSelectSubnet={onSelectSubnet}
      onSelectBlock={onSelectBlock}
    />,
  );
  await waitFor(() => expect(treeitem("10.142.1.0/24")).toBeTruthy());
  await settle();
}

/** Right-click `row`; the open menu as {label: disabled}. */
async function menuItems(row: HTMLElement) {
  row.focus();
  fireEvent.contextMenu(row, { clientX: 10, clientY: 10 });
  await waitFor(() =>
    expect(
      document.querySelectorAll('[role="menuitem"]').length,
    ).toBeGreaterThan(0),
  );
  return Object.fromEntries(
    Array.from(document.querySelectorAll('[role="menuitem"]')).map((i) => [
      (i.textContent ?? "").trim(),
      i.getAttribute("aria-disabled") === "true" ||
        i.hasAttribute("data-disabled"),
    ]),
  );
}
const item = (label: string) =>
  Array.from(document.querySelectorAll('[role="menuitem"]')).find(
    (i) => (i.textContent ?? "").trim() === label,
  ) as HTMLElement;

describe("the tree's right-click menus (#3392)", () => {
  it("disables a space's write items for a Viewer and keeps Collapse", async () => {
    signInAs(VIEWER);
    await openTree();
    const m = await menuItems(
      document.querySelector("[title='Collapse']")!
        .parentElement as HTMLElement,
    );
    expect(m["New Block…"]).toBe(true);
    expect(m["New Subnet…"]).toBe(true);
    expect(m["Edit Space…"]).toBe(true);
    expect(m["Collapse"]).toBe(false);
    fireEvent.click(item("New Subnet…"));
    await settle();
    expect(headings()).not.toContain("New Subnet");
  });

  it("disables a block's write items for a Viewer", async () => {
    signInAs(VIEWER);
    await openTree();
    const m = await menuItems(
      treeitem("10.142.0.0/16").firstElementChild as HTMLElement,
    );
    expect(m["New child block…"]).toBe(true);
    expect(m["New subnet…"]).toBe(true);
    expect(m["Edit…"]).toBe(true);
    expect(m["Delete…"]).toBe(true);
    fireEvent.click(item("New subnet…"));
    await settle();
    expect(headings()).not.toContain("New Subnet");
  });

  it("disables a subnet's Edit and Delete, and leaves Allocate IP", async () => {
    signInAs(VIEWER);
    await openTree();
    const m = await menuItems(treeitem("10.142.1.0/24"));
    expect(m["Edit…"]).toBe(true);
    expect(m["Delete…"]).toBe(true);
    expect(m["Allocate IP"]).toBe(false);
    fireEvent.click(item("Edit…"));
    await settle();
    expect(q('[role="dialog"]')).toBeNull();
  });

  it("makes the rows undraggable for a Viewer, draggable for an editor", async () => {
    const blockRow = () =>
      treeitem("10.142.0.0/16").firstElementChild as HTMLElement;
    signInAs(VIEWER);
    await openTree();
    // Not draggable: nothing announces it as a drag source.
    expect(treeitem("10.142.1.0/24").hasAttribute("aria-roledescription")).toBe(
      false,
    );
    expect(blockRow().hasAttribute("aria-roledescription")).toBe(false);
    cleanup();

    signInAs([
      ["read", "*"],
      ["write", "subnet"],
      ["write", "ip_block"],
    ]);
    await openTree();
    expect(treeitem("10.142.1.0/24").getAttribute("aria-roledescription")).toBe(
      "draggable",
    );
    expect(blockRow().getAttribute("aria-roledescription")).toBe("draggable");
  });

  it("leaves a Viewer's rows enabled and selectable: only the drag is gone", async () => {
    signInAs(VIEWER);
    const pickSubnet = vi.fn();
    const pickBlock = vi.fn();
    await openTree(pickSubnet, pickBlock);
    const row = treeitem("10.142.1.0/24");
    const blockRow = treeitem("10.142.0.0/16").firstElementChild as HTMLElement;
    // A row the Viewer may open must not read as unavailable (dnd-kit sets
    // aria-disabled="true" on a disabled draggable; a screen reader then
    // announces the row dimmed, and Playwright refuses to click inside it).
    expect(row.getAttribute("aria-disabled")).not.toBe("true");
    expect(blockRow.getAttribute("aria-disabled")).not.toBe("true");
    expect(
      document.querySelector('[aria-disabled="true"][role="treeitem"]'),
    ).toBeNull();
    fireEvent.click(row);
    expect(pickSubnet).toHaveBeenCalledWith(subnet);
    fireEvent.click(blockRow.querySelector("button:not([aria-label])")!);
    expect(pickBlock).toHaveBeenCalled();
  });

  it("shows the reason on a disabled item and ignores Enter on it", async () => {
    signInAs(VIEWER);
    await openTree();
    await menuItems(treeitem("10.142.0.0/16").firstElementChild as HTMLElement);
    const newSubnet = item("New subnet…");
    expect(newSubnet.getAttribute("title")).toBe(
      "Requires write permission on subnets",
    );
    // The reason is only seen on hover if the item takes pointer events.
    expect(newSubnet.className).not.toMatch(/pointer-events-none/);
    newSubnet.focus();
    fireEvent.keyDown(newSubnet, { key: "Enter" });
    fireEvent.keyDown(newSubnet, { key: " " });
    await settle();
    expect(headings()).not.toContain("New Subnet");
  });

  it("enables Edit Space for a grant scoped to that space", async () => {
    signInAs([
      ["read", "*"],
      ["write", "ip_space", "sp-1"],
    ]);
    await openTree();
    const m = await menuItems(
      document.querySelector("[title='Collapse']")!
        .parentElement as HTMLElement,
    );
    expect(m["Edit Space…"]).toBe(false);
    expect(m["New Block…"]).toBe(true);
  });

  it("enables a block's Edit for a grant scoped to that block, not its Delete", async () => {
    signInAs([
      ["read", "*"],
      ["write", "ip_block", "blk-1"],
    ]);
    await openTree();
    const m = await menuItems(
      treeitem("10.142.0.0/16").firstElementChild as HTMLElement,
    );
    expect(m["Edit…"]).toBe(false);
    expect(m["Delete…"]).toBe(true);
    expect(m["New child block…"]).toBe(true);
  });

  it("offers a superadmin every item enabled", async () => {
    signInAs("superadmin");
    await openTree();
    const m = await menuItems(treeitem("10.142.1.0/24"));
    expect(m["Edit…"]).toBe(false);
    expect(m["Delete…"]).toBe(false);
    fireEvent.click(item("Edit…"));
    await waitFor(() => expect(q('[role="dialog"]')).toBeTruthy());
  });
});

describe("an orphan address's right-click (#3392)", () => {
  async function openOrphan() {
    answers.ipamApi = {
      listAddresses: () =>
        Promise.resolve([
          {
            id: "a",
            subnet_id: "sub-1",
            address: "10.142.1.10",
            status: "orphan",
            role: null,
            hostname: "h-orphan",
            fqdn: null,
            description: "",
            mac_address: null,
            tags: {},
            custom_fields: {},
            created_at: STAMP,
            modified_at: STAMP,
          },
        ]),
    };
    answers.dhcpApi = { listScopesBySubnet: () => Promise.resolve([]) };
    wrap(<SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />);
    await screen.findByText("10.142.1.10");
    await settle();
    return screen.getByText("10.142.1.10").closest("tr") as HTMLElement;
  }

  it("disables Restore and Delete Forever for a Viewer and sends nothing", async () => {
    signInAs(VIEWER);
    const restore = vi.fn(() => Promise.resolve({}));
    const row = await openOrphan();
    answers.ipamApi.updateAddress = restore;
    const m = await menuItems(row);
    expect(m["Restore"]).toBe(true);
    expect(m["Delete Forever…"]).toBe(true);
    fireEvent.click(item("Restore"));
    await settle();
    expect(restore).not.toHaveBeenCalled();
    fireEvent.click(item("Delete Forever…"));
    await settle();
    expect(headings()).not.toContain("Permanently Delete");
  });

  it("disables the purge, inline and right-click, without delete; keeps Restore", async () => {
    signInAs([
      ["read", "*"],
      ["write", "subnet"],
    ]);
    const row = await openOrphan();
    const purge = row.querySelector(
      'button[aria-label="Permanently delete 10.142.1.10"]',
    ) as HTMLButtonElement;
    expect(purge).toBeTruthy();
    expect(purge.disabled).toBe(true);
    fireEvent.click(purge);
    await settle();
    expect(headings()).not.toContain("Permanently Delete");
    const m = await menuItems(row);
    expect(m["Restore"]).toBe(false);
    expect(m["Delete Forever…"]).toBe(true);
  });

  it("keeps both for a superadmin", async () => {
    signInAs("superadmin");
    const row = await openOrphan();
    const m = await menuItems(row);
    expect(m["Restore"]).toBe(false);
    expect(m["Delete Forever…"]).toBe(false);
  });
});

describe("Find Free and the allocation band (#3391)", () => {
  async function openBlock() {
    answers.ipamApi = {
      listBlocks: () => Promise.resolve([block]),
      listTemplates: () => Promise.resolve([]),
      blockFreeSpace: () =>
        Promise.resolve([
          {
            network: "10.142.0.0/24",
            first: "10.142.0.0",
            last: "10.142.0.255",
            size: 256,
            prefix_len: 24,
          },
        ]),
      findFreeSpace: () =>
        Promise.resolve({
          candidates: [
            {
              cidr: "10.142.16.0/24",
              parent_block_id: "blk-1",
              parent_block_cidr: "10.142.0.0/16",
              free_addresses: 254,
            },
          ],
          summary: {},
        }),
    };
    answers.customFieldsApi = { list: () => Promise.resolve([]) };
    wrap(
      <BlockDetailView
        block={block}
        spaceName="lab"
        ancestors={[]}
        allBlocks={[block]}
        allSubnets={[]}
        space={space}
        onSelectSpace={() => {}}
        onSelectBlock={() => {}}
        onSelectSubnet={() => {}}
      />,
    );
    await settle();
  }
  const band = () =>
    q('button[aria-label^="Free 10.142.0.0/24"]') as HTMLButtonElement | null;

  async function runFindFree() {
    fireEvent.click(await screen.findByRole("button", { name: /Tools/ }));
    fireEvent.click(await screen.findByText("Find Free…"));
    fireEvent.click(await screen.findByRole("button", { name: "Find" }));
    return (await screen.findByText("Create subnet here")).closest(
      "button",
    ) as HTMLButtonElement;
  }

  it("disables a Viewer's Create subnet here and free segment", async () => {
    signInAs(VIEWER);
    await openBlock();
    await waitFor(() => expect(band()).toBeTruthy());
    expect(band()!.disabled).toBe(true);
    fireEvent.click(band()!);
    await settle();
    expect(headings()).not.toContain("New Subnet");

    const pick = await runFindFree();
    expect(pick.disabled).toBe(true);
    fireEvent.click(pick);
    await settle();
    expect(headings()).not.toContain("New Subnet");
  });

  it("keeps both for an editor", async () => {
    signInAs([
      ["read", "*"],
      ["write", "subnet"],
    ]);
    await openBlock();
    await waitFor(() => expect(band()).toBeTruthy());
    await waitFor(() => expect(band()!.disabled).toBe(false));
    fireEvent.click(band()!);
    await waitFor(() => expect(headings()).toContain("New Subnet"));
    cleanup();

    signInAs([
      ["read", "*"],
      ["write", "subnet"],
    ]);
    await openBlock();
    const pick = await runFindFree();
    expect(pick.disabled).toBe(false);
    fireEvent.click(pick);
    await waitFor(() => expect(headings()).toContain("New Subnet"));
  });
});

describe("a regular address's Delete (#3409)", () => {
  async function openRegular() {
    answers.ipamApi = {
      listAddresses: () =>
        Promise.resolve([
          {
            id: "r",
            subnet_id: "sub-1",
            address: "10.142.1.20",
            status: "allocated",
            role: null,
            hostname: "h-reg",
            fqdn: null,
            description: "",
            mac_address: null,
            tags: {},
            custom_fields: {},
            created_at: STAMP,
            modified_at: STAMP,
          },
        ]),
    };
    answers.dhcpApi = { listScopesBySubnet: () => Promise.resolve([]) };
    wrap(<SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />);
    await screen.findByText("10.142.1.20");
    await settle();
    return screen.getByText("10.142.1.20").closest("tr") as HTMLElement;
  }
  const inline = (row: HTMLElement) =>
    row.querySelector(
      'button[aria-label="Delete 10.142.1.20"]',
    ) as HTMLButtonElement;

  it("disables it, inline and right-click, with write but not delete", async () => {
    signInAs([
      ["read", "*"],
      ["write", "subnet"],
    ]);
    const del = vi.fn(() => Promise.resolve({}));
    const row = await openRegular();
    answers.ipamApi.deleteAddress = del;
    const btn = inline(row);
    expect(btn).toBeTruthy();
    expect(btn.disabled).toBe(true);
    expect(btn.title).toMatch(/delete/i);
    fireEvent.click(btn);
    await settle();
    const m = await menuItems(row);
    expect(m["Edit…"]).toBe(false);
    expect(m["Delete…"]).toBe(true);
    expect(item("Delete…").getAttribute("title")).toMatch(/delete/i);
    fireEvent.click(item("Delete…"));
    await settle();
    expect(q('[role="dialog"]')).toBeNull();
    expect(del).not.toHaveBeenCalled();
  });

  it("still works for an editor with delete", async () => {
    signInAs([
      ["read", "*"],
      ["write", "subnet"],
      ["delete", "*"],
    ]);
    const row = await openRegular();
    expect(inline(row).disabled).toBe(false);
    fireEvent.click(inline(row));
    await waitFor(() => expect(q('[role="dialog"]')).toBeTruthy());
    cleanup();
    const row2 = await openRegular();
    const m = await menuItems(row2);
    expect(m["Delete…"]).toBe(false);
  });
});

describe("an address's Delete matches the server's gate (#3409)", () => {
  // The IPAM Editor builtin role (``main.py``): admin on the IPAM types.
  const IPAM_EDITOR: [string, string][] = [
    ["admin", "ip_space"],
    ["admin", "ip_block"],
    ["admin", "subnet"],
    ["admin", "ip_address"],
    ["admin", "address_set"],
  ];
  const ROW = {
    id: "r",
    subnet_id: "sub-1",
    address: "10.142.1.20",
    status: "allocated",
    role: null,
    hostname: "h-reg",
    fqdn: null,
    description: "",
    mac_address: null,
    tags: {},
    custom_fields: {},
    created_at: STAMP,
    modified_at: STAMP,
  };
  async function open() {
    answers.ipamApi = { listAddresses: () => Promise.resolve([ROW]) };
    answers.dhcpApi = { listScopesBySubnet: () => Promise.resolve([]) };
    wrap(<SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />);
    await screen.findByText("10.142.1.20");
    await settle();
    return screen.getByText("10.142.1.20").closest("tr") as HTMLElement;
  }
  const inline = (row: HTMLElement) =>
    row.querySelector(
      'button[aria-label="Delete 10.142.1.20"]',
    ) as HTMLButtonElement;
  /** Click the row; the detail modal's buttons by their text. */
  async function detailButtons(row: HTMLElement) {
    fireEvent.click(row);
    await waitFor(() => expect(q('[role="dialog"]')).toBeTruthy());
    await settle();
    return Array.from(
      (q('[role="dialog"]') as HTMLElement).querySelectorAll("button"),
    ).map((b) => (b.textContent ?? "").trim());
  }

  it("offers no Delete in the detail modal with write but not delete", async () => {
    signInAs([
      ["read", "*"],
      ["write", "subnet"],
    ]);
    const buttons = await detailButtons(await open());
    expect(buttons).toContain("Edit");
    expect(buttons).not.toContain("Delete");
  });

  it("offers it to the IPAM Editor role, in the modal and inline", async () => {
    signInAs([["read", "*"], ...IPAM_EDITOR]);
    const row = await open();
    expect(inline(row).disabled).toBe(false);
    expect(await detailButtons(row)).toContain("Delete");
  });

  it("offers it to a superadmin", async () => {
    signInAs("superadmin");
    const row = await open();
    expect(inline(row).disabled).toBe(false);
    expect(await detailButtons(row)).toContain("Delete");
  });

  it("offers it on a delete grant scoped to any address set, as the gate admits", async () => {
    // ``_ADDRESS_SET_ROUTES`` admits DELETE /addresses/{id} on ANY delete
    // grant on an address set (``has_any_grant_for``); the handler then
    // wants write on the row, here through the subnet.
    signInAs([
      ["read", "*"],
      ["write", "subnet"],
      ["delete", "address_set", "set-elsewhere"],
    ]);
    const row = await open();
    expect(inline(row).disabled).toBe(false);
  });

  it("keeps Clean Orphans disabled on an address-set delete grant", async () => {
    // POST /subnets/{id}/orphans/purge is not on the address-set allow-list:
    // it takes delete on subnet, which this role does not hold.
    signInAs([
      ["read", "*"],
      ["write", "subnet"],
      ["delete", "address_set"],
    ]);
    await open();
    fireEvent.click(q('button[title="Subnet tools — scan, clean, reshape"]')!);
    const clean = await waitFor(() => {
      const b = Array.from(
        document.querySelectorAll('[role="menu"] [role="menuitem"]'),
      ).find((e) => e.textContent?.includes("Clean Orphans"));
      expect(b).toBeTruthy();
      return b as HTMLButtonElement;
    });
    expect(clean.disabled).toBe(true);
    expect(clean.title).toMatch(/delete/i);
  });
});
