/**
 * @vitest-environment jsdom
 *
 * Edit Zone, Edit View and Edit Subnet read the object fresh on open and send
 * only what the operator changed (#3269). Each dialog is handed a stale row
 * (what the page cached) while the API holds the newer value: the dialog must
 * show the newer value, a Save with no edits must send nothing, and one edit
 * must send only that field.
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
import type { ReactNode } from "react";
import type { DNSView, DNSZone, Subnet } from "@/lib/api";

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

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { ZoneModal, ViewModal, SyncResultModal } =
  await import("@/pages/dns/DNSPage");
const { EditSubnetModal } = await import("@/pages/ipam/IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const save = () =>
  fireEvent.click(screen.getByRole("button", { name: /^Save/ }));

describe("Edit Zone (#3269)", () => {
  const stale = {
    id: "z-1",
    group_id: "g-1",
    name: "xp.test.",
    zone_type: "primary",
    kind: "forward",
    view_id: null,
    primary_ns: "",
    admin_email: "",
    ttl: 3600,
    color: null,
    domain_id: null,
    customer_id: null,
    forwarders: [],
    masters: [],
  } as unknown as DNSZone;
  const fresh = { ...stale, ttl: 7200 } as DNSZone;
  const props = { groupId: "g-1", views: [] };

  it("shows the stored TTL; an untouched Save sends nothing", async () => {
    const updateZone = vi.fn(() => Promise.resolve(fresh));
    answers.dnsApi = { listZones: () => Promise.resolve([fresh]), updateZone };
    const onClose = vi.fn();
    open(<ZoneModal {...props} zone={stale} onClose={onClose} />);
    await screen.findByDisplayValue("7200");
    expect(screen.queryByDisplayValue("3600")).toBeNull();
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateZone).not.toHaveBeenCalled();
  });

  it("sends only the field the operator changed", async () => {
    const updateZone = vi.fn(() => Promise.resolve(fresh));
    answers.dnsApi = { listZones: () => Promise.resolve([fresh]), updateZone };
    open(<ZoneModal {...props} zone={stale} onClose={() => {}} />);
    const box = await screen.findByDisplayValue("7200");
    fireEvent.change(box, { target: { value: "9000" } });
    save();
    await waitFor(() => expect(updateZone).toHaveBeenCalled());
    expect(updateZone).toHaveBeenCalledWith("g-1", "z-1", { ttl: 9000 });
  });
});

describe("Edit View (#3269)", () => {
  const stale = {
    id: "v-1",
    group_id: "g-1",
    name: "internal",
    description: "old",
    match_clients: ["any"],
    match_destinations: [],
    recursion: true,
    order: 0,
  } as unknown as DNSView;
  const fresh = { ...stale, description: "new" } as DNSView;

  it("shows the stored description; an untouched Save sends nothing", async () => {
    const updateView = vi.fn(() => Promise.resolve(fresh));
    answers.dnsApi = { listViews: () => Promise.resolve([fresh]), updateView };
    const onClose = vi.fn();
    open(<ViewModal groupId="g-1" view={stale} onClose={onClose} />);
    await screen.findByDisplayValue("new");
    expect(screen.queryByDisplayValue("old")).toBeNull();
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateView).not.toHaveBeenCalled();
  });

  it("sends only the field the operator changed", async () => {
    const updateView = vi.fn(() => Promise.resolve(fresh));
    answers.dnsApi = { listViews: () => Promise.resolve([fresh]), updateView };
    open(<ViewModal groupId="g-1" view={stale} onClose={() => {}} />);
    const box = await screen.findByDisplayValue("new");
    fireEvent.change(box, { target: { value: "newer" } });
    save();
    await waitFor(() => expect(updateView).toHaveBeenCalled());
    expect(updateView).toHaveBeenCalledWith("g-1", "v-1", {
      description: "newer",
    });
  });
});

describe("Edit Subnet (#3269)", () => {
  const stale = {
    id: "s-1",
    space_id: "sp-1",
    block_id: "b-1",
    network: "10.1.0.0/24",
    name: "lan",
    description: "old",
    status: "active",
    custom_fields: {},
    dns_inherit_settings: true,
    dhcp_inherit_settings: true,
    ddns_inherit_settings: true,
  } as unknown as Subnet;
  const fresh = { ...stale, description: "new" } as Subnet;

  it("shows the stored description; an untouched Save sends nothing", async () => {
    const updateSubnet = vi.fn(() => Promise.resolve(fresh));
    answers.ipamApi = { getSubnet: () => Promise.resolve(fresh), updateSubnet };
    const onClose = vi.fn();
    open(<EditSubnetModal subnet={stale} onClose={onClose} />);
    await screen.findByDisplayValue("new");
    expect(screen.queryByDisplayValue("old")).toBeNull();
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateSubnet).not.toHaveBeenCalled();
  });

  it("sends only the field the operator changed", async () => {
    const updateSubnet = vi.fn(() => Promise.resolve(fresh));
    answers.ipamApi = { getSubnet: () => Promise.resolve(fresh), updateSubnet };
    open(<EditSubnetModal subnet={stale} onClose={() => {}} />);
    const box = await screen.findByDisplayValue("new");
    fireEvent.change(box, { target: { value: "newer" } });
    save();
    await waitFor(() => expect(updateSubnet).toHaveBeenCalled());
    expect(updateSubnet).toHaveBeenCalledWith("s-1", {
      description: "newer",
    });
  });
});

describe("Edit Subnet's DNS inheritance toggle (#3269)", () => {
  const base = {
    id: "s-2",
    space_id: "sp-1",
    block_id: "b-1",
    network: "10.2.0.0/24",
    name: "lan2",
    description: "",
    status: "active",
    custom_fields: {},
    dhcp_inherit_settings: true,
    ddns_inherit_settings: true,
  };

  async function toggleDnsInherit(subnet: Subnet) {
    const updateSubnet = vi.fn(() => Promise.resolve(subnet));
    answers.ipamApi = {
      getSubnet: () => Promise.resolve(subnet),
      updateSubnet,
    };
    open(<EditSubnetModal subnet={subnet} onClose={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "DNS" }));
    fireEvent.click(screen.getByLabelText(/Inherit from parent/));
    save();
    await waitFor(() => expect(updateSubnet).toHaveBeenCalled());
    return (updateSubnet.mock.calls[0] as unknown[])[1];
  }

  it("turning inheritance on clears the subnet's own pins", async () => {
    const body = await toggleDnsInherit({
      ...base,
      dns_inherit_settings: false,
      dns_group_ids: ["g-1"],
      dns_zone_id: "z-1",
      dns_additional_zone_ids: ["z-2"],
    } as unknown as Subnet);
    expect(body).toEqual({
      dns_inherit_settings: true,
      dns_group_ids: null,
      dns_zone_id: null,
      dns_additional_zone_ids: null,
    });
  });

  it("turning inheritance off sends the values the dialog shows", async () => {
    const body = await toggleDnsInherit({
      ...base,
      dns_inherit_settings: true,
      dns_group_ids: ["g-1"],
      dns_zone_id: "z-1",
      dns_additional_zone_ids: [],
    } as unknown as Subnet);
    expect(body).toEqual({
      dns_inherit_settings: false,
      dns_group_ids: ["g-1"],
      dns_zone_id: "z-1",
      dns_additional_zone_ids: [],
    });
  });
});

describe("Sync with server failure (#3270)", () => {
  const failed = { ok: false as const, error: "No primary DNS server" };
  const render_ = (drivers: string[]) =>
    open(
      <SyncResultModal
        zoneName="xp.test."
        result={failed}
        drivers={drivers}
        onClose={() => {}}
      />,
    );

  it("shows the reason and never says only one driver can pull", () => {
    render_([]);
    expect(screen.getByText("No primary DNS server")).toBeTruthy();
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/only Windows DNS/i);
    expect(text).not.toMatch(/DNS Manager/);
  });

  it("points to DNS Manager only for a Windows DNS group", () => {
    render_(["bind9"]);
    expect(document.body.textContent).not.toMatch(/DNS Manager/);
    cleanup();
    render_(["windows_dns"]);
    expect(document.body.textContent).toMatch(/DNS Manager/);
  });
});
