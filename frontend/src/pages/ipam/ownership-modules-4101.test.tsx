/**
 * @vitest-environment jsdom
 *
 * #4101 — Customer / Site are feature modules (`network.customer`,
 * `network.site`). With one off, the create / edit dialogs must not show its
 * field (label and hint included), and an edit made while it is off must not
 * clear the stored id. ``ready: false`` is its own case: `enabled()` answers
 * true while the module set loads, which would flash the field in.
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
import type { Subnet } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
const calls: string[] = [];
const mods = { ready: true, off: new Set<string>() };

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
                : (...args: unknown[]) => {
                    calls.push(`${name}.${String(method)}`);
                    return (answers[name]?.[method] ?? pending)(...args);
                  },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    ready: mods.ready,
    enabled: (id: string) => !mods.off.has(id),
  }),
}));

const { CreateSubnetModal, CreateBlockModal, EditSubnetModal } =
  await import("./IPAMPage");

beforeEach(() => {
  mods.ready = true;
  mods.off = new Set();
  calls.length = 0;
});

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function newSubnet() {
  answer("ipamApi", "listBlocks", () => Promise.resolve([]));
  answer("ipamApi", "listTemplates", () => Promise.resolve([]));
  open(<CreateSubnetModal spaceId="sp-1" onClose={() => {}} />);
}

describe("New Subnet ownership fields (#4101)", () => {
  it("shows Customer and Site while both modules are on (control)", async () => {
    newSubnet();
    expect(await screen.findByText("Customer")).toBeTruthy();
    expect(screen.getByText("Site")).toBeTruthy();
    expect(screen.getByText("Logical owner of this subnet.")).toBeTruthy();
  });

  it("has no Customer field, label or request with network.customer off", async () => {
    mods.off = new Set(["network.customer"]);
    newSubnet();
    expect(await screen.findByText("Site")).toBeTruthy();
    expect(screen.queryByText("Customer")).toBeNull();
    expect(screen.queryByText("Logical owner of this subnet.")).toBeNull();
    expect(calls).not.toContain("customersApi.list");
  });

  it("has no Site field, label or request with network.site off", async () => {
    mods.off = new Set(["network.site"]);
    newSubnet();
    expect(await screen.findByText("Customer")).toBeTruthy();
    expect(screen.queryByText("Site")).toBeNull();
    expect(screen.queryByText("Physical location of this subnet.")).toBeNull();
    expect(calls).not.toContain("sitesApi.list");
  });

  it("shows neither before the module set has loaded", async () => {
    mods.ready = false;
    newSubnet();
    await screen.findByRole("button", { name: "General" });
    expect(screen.queryByText("Customer")).toBeNull();
    expect(screen.queryByText("Site")).toBeNull();
    expect(calls).not.toContain("customersApi.list");
    expect(calls).not.toContain("sitesApi.list");
  });
});

describe("New Block ownership fields (#4101)", () => {
  async function newBlock() {
    answer("ipamApi", "listBlocks", () => Promise.resolve([]));
    open(<CreateBlockModal spaceId="sp-1" onClose={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "Networking" }));
    await screen.findByText("Origin ASN (BGP)");
  }

  it("shows Customer and Site while both modules are on (control)", async () => {
    await newBlock();
    expect(screen.getByText("Customer")).toBeTruthy();
    expect(screen.getByText("Site")).toBeTruthy();
  });

  it("has neither with both modules off", async () => {
    mods.off = new Set(["network.customer", "network.site"]);
    await newBlock();
    expect(screen.queryByText("Customer")).toBeNull();
    expect(screen.queryByText("Site")).toBeNull();
  });
});

describe("Edit Subnet with the modules off keeps the stored owner (#4101)", () => {
  const subnet = {
    id: "sub-1",
    space_id: "sp-1",
    block_id: "blk-1",
    network: "10.1.0.0/24",
    name: "named",
    description: "",
    vlan_id: null,
    vxlan_id: null,
    gateway: null,
    status: "active",
    tags: {},
    custom_fields: {},
    utilization_percent: 0,
    allocated_ips: 0,
    total_ips: 254,
    customer_id: "cust-1",
    site_id: "site-1",
  } as unknown as Subnet;

  it("hides the fields and sends neither id as cleared", async () => {
    mods.off = new Set(["network.customer", "network.site"]);
    const updateSubnet = vi.fn((..._a: unknown[]) => Promise.resolve(subnet));
    answer("ipamApi", "updateSubnet", updateSubnet);
    answer("ipamApi", "getSubnet", () => Promise.resolve(subnet));
    open(<EditSubnetModal subnet={subnet} onClose={() => {}} />);
    fireEvent.change(await screen.findByDisplayValue("named"), {
      target: { value: "renamed" },
    });
    expect(screen.queryByText("Customer")).toBeNull();
    expect(screen.queryByText("Site")).toBeNull();
    const save = screen.getByRole("button", {
      name: "Save",
    }) as HTMLButtonElement;
    await waitFor(() => expect(save.disabled).toBe(false));
    fireEvent.click(save);
    await waitFor(() => expect(updateSubnet).toHaveBeenCalledTimes(1));
    // Only the change is sent: customer_id / site_id stay untouched.
    expect(updateSubnet.mock.calls[0][1]).toEqual({ name: "renamed" });
  });
});
