/**
 * @vitest-environment jsdom
 *
 * #3466: the IP space, block and subnet dialogs and the subnet view for a
 * user holding only the built-in IPAM Editor role, which reads none of DNS
 * or DHCP. The dialogs' DNS tab asked GET /dns/groups (read on `dns_group`)
 * and each held group's zones (read on `dns_zone`), and said "No groups
 * configured." over a group the space holds; their DHCP tab asked
 * GET /dhcp/server-groups (read on `dhcp_server`); and the subnet view asked
 * its DHCP scopes (read on `dhcp_scope`) on every opening, which is the
 * refusal the issue saw when the IP detail opened from it. Each refusal is a
 * 403 and a denied audit row. None is asked now without its grant, and a
 * stored group or zone reads as linked but not shown.
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
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import type { Subnet } from "@/lib/api";

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

const { CreateSpaceModal, EditSpaceModal, EditBlockModal, SubnetDetail } =
  await import("./IPAMPage");

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

/** The built-in IPAM Editor role's grants (backend app/main.py). */
const IPAM_EDITOR: G[] = [
  ...[
    "ip_space",
    "ip_block",
    "subnet",
    "ip_address",
    "address_set",
    "vlan",
    "nat_mapping",
    "custom_field",
    "manage_ipam_templates",
    "customer",
    "site",
    "provider",
    "network_service",
  ].map((t): G => ["admin", t, null]),
  ["read", "alert", null],
];

/** The same, with the DNS and DHCP reads the dialogs and the view ask. */
const WITH_READS: G[] = [
  ...IPAM_EDITOR,
  ["read", "dns_group", null],
  ["read", "dns_zone", null],
  ["read", "dhcp_server", null],
  ["read", "dhcp_scope", null],
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

/** Spies on the DNS and DHCP reads; each refuses the way the API does. */
function spyReads() {
  const dnsGroups = vi.fn(() => Promise.reject(refusal("dns_group")));
  const dnsZones = vi.fn(() => Promise.reject(refusal("dns_zone")));
  const dhcpGroups = vi.fn(() => Promise.reject(refusal("dhcp_server")));
  const dhcpScopes = vi.fn(() => Promise.reject(refusal("dhcp_scope")));
  answer("dnsApi", "listGroups", dnsGroups);
  answer("dnsApi", "listZones", dnsZones);
  answer("dhcpApi", "listGroups", dhcpGroups);
  answer("dhcpApi", "listScopesBySubnet", dhcpScopes);
  return { dnsGroups, dnsZones, dhcpGroups, dhcpScopes };
}

async function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 80));
  });
}

const SPACE = {
  id: "sp-1",
  name: "corp",
  description: "old",
  color: null,
  tags: {},
  dns_group_ids: ["g-1"],
  dns_zone_id: "z-1",
  dns_additional_zone_ids: ["z-2"],
  dhcp_server_group_id: "dg-1",
  vrf_id: null,
  asn_id: null,
  customer_id: null,
};

function linked(sel: HTMLSelectElement) {
  expect(sel.disabled).toBe(true);
  expect(sel.selectedOptions[0].textContent).toBe(
    "Linked (not visible to your role)",
  );
}

describe("IP space dialogs for the IPAM Editor (#3466)", () => {
  it("Edit IP Space asks no DNS group or zone list and says the space's group and zones are linked", async () => {
    signInAs(IPAM_EDITOR);
    const reads = spyReads();
    answer("ipamApi", "getSpace", () => Promise.resolve(SPACE));
    await open(
      <EditSpaceModal
        space={SPACE as never}
        onClose={() => {}}
        onDeleted={() => {}}
      />,
    );
    linked(
      (await screen.findByTitle(
        /cannot read DNS server groups/,
      )) as HTMLSelectElement,
    );
    linked(
      (await screen.findByTitle(
        /cannot read DNS zones, so this/,
      )) as HTMLSelectElement,
    );
    expect(
      screen.getByText(/1 linked \(not visible to your role\)/),
    ).toBeTruthy();
    expect(screen.queryByText(/No groups configured/)).toBeNull();
    expect(reads.dnsGroups).not.toHaveBeenCalled();
    expect(reads.dnsZones).not.toHaveBeenCalled();
  });

  it("Edit IP Space's DHCP tab asks no DHCP server group list and says the space's group is linked", async () => {
    signInAs(IPAM_EDITOR);
    const reads = spyReads();
    answer("ipamApi", "getSpace", () => Promise.resolve(SPACE));
    await open(
      <EditSpaceModal
        space={SPACE as never}
        onClose={() => {}}
        onDeleted={() => {}}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "DHCP" }));
    linked(
      (await screen.findByTitle(
        /cannot read DHCP server groups/,
      )) as HTMLSelectElement,
    );
    expect(screen.queryByText(/No DHCP server groups configured/)).toBeNull();
    expect(reads.dhcpGroups).not.toHaveBeenCalled();
  });

  it("New IP Space asks no DNS or DHCP group list and offers None, disabled, with the reason", async () => {
    signInAs(IPAM_EDITOR);
    const reads = spyReads();
    await open(<CreateSpaceModal onClose={() => {}} />);
    const dns = (await screen.findByTitle(
      /cannot read DNS server groups/,
    )) as HTMLSelectElement;
    expect(dns.disabled).toBe(true);
    expect(dns.selectedOptions[0].textContent).toBe("\u2014 None \u2014");
    fireEvent.click(screen.getByRole("button", { name: "DHCP" }));
    const dhcp = (await screen.findByTitle(
      /cannot read DHCP server groups/,
    )) as HTMLSelectElement;
    expect(dhcp.disabled).toBe(true);
    expect(dhcp.selectedOptions[0].textContent).toBe("\u2014 None \u2014");
    expect(reads.dnsGroups).not.toHaveBeenCalled();
    expect(reads.dhcpGroups).not.toHaveBeenCalled();
  });

  it("Edit Block's inherited DNS line names no raw zone id for a user who may not read zones", async () => {
    signInAs(IPAM_EDITOR);
    const reads = spyReads();
    const block = {
      id: "b-1",
      space_id: "sp-1",
      parent_block_id: null,
      network: "10.98.0.0/16",
      name: "core",
      description: "",
      tags: {},
      custom_fields: {},
      dns_inherit_settings: true,
      dhcp_inherit_settings: true,
      vrf_id: null,
      asn_id: null,
      customer_id: null,
      site_id: null,
    };
    answer("ipamApi", "getBlock", () => Promise.resolve(block));
    answer("ipamApi", "getEffectiveSpaceDns", () =>
      Promise.resolve({
        dns_group_ids: ["g-1"],
        dns_zone_id: "z-1",
        dns_additional_zone_ids: [],
        inherited_from_block_id: null,
      }),
    );
    await open(<EditBlockModal block={block as never} onClose={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "DNS" }));
    await waitFor(() =>
      expect(screen.getByText(/Inheriting from/).textContent).toMatch(
        /zone: linked, not shown/,
      ),
    );
    expect(screen.getByText(/Inheriting from/).textContent).not.toMatch(/z-1/);
    expect(reads.dnsZones).not.toHaveBeenCalled();
  });

  it("still asks every list, and lists the groups, for a user who may read them", async () => {
    signInAs(WITH_READS);
    const dnsGroups = vi.fn(() =>
      Promise.resolve([{ id: "g-1", name: "internal" }]),
    );
    const dnsZones = vi.fn(() =>
      Promise.resolve([{ id: "z-1", name: "corp.example." }]),
    );
    const dhcpGroups = vi.fn(() =>
      Promise.resolve([{ id: "dg-1", name: "kea-pair" }]),
    );
    answer("dnsApi", "listGroups", dnsGroups);
    answer("dnsApi", "listZones", dnsZones);
    answer("dhcpApi", "listGroups", dhcpGroups);
    answer("ipamApi", "getSpace", () => Promise.resolve(SPACE));
    await open(
      <EditSpaceModal
        space={SPACE as never}
        onClose={() => {}}
        onDeleted={() => {}}
      />,
    );
    expect(
      await screen.findByRole("option", { name: "internal" }),
    ).toBeTruthy();
    expect(
      await screen.findAllByRole("option", { name: "corp.example." }),
    ).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "DHCP" }));
    expect(
      await screen.findByRole("option", { name: "kea-pair" }),
    ).toBeTruthy();
    expect(dnsGroups).toHaveBeenCalled();
    expect(dnsZones).toHaveBeenCalledWith("g-1");
    expect(dhcpGroups).toHaveBeenCalled();
  });
});

const STAMP = "2026-11-04T00:00:00Z";
const SUBNET = {
  id: "sub-1",
  space_id: "sp-1",
  block_id: "blk-1",
  network: "10.1.0.0/24",
  name: "lab",
  total_ips: 254,
  allocated_ips: 0,
  utilization_percent: 0,
  dns_group_ids: [],
  created_at: STAMP,
  modified_at: STAMP,
} as unknown as Subnet;

describe("the subnet view for the IPAM Editor (#3466)", () => {
  it("asks no DHCP scope list of a user who may not read scopes", async () => {
    signInAs(IPAM_EDITOR);
    const reads = spyReads();
    answer("ipamApi", "listAddresses", () => Promise.resolve([]));
    await open(<SubnetDetail subnet={SUBNET} onSubnetEdited={() => {}} />);
    await act(async () => {
      await new Promise((r) => setTimeout(r, 80));
    });
    expect(reads.dhcpScopes).not.toHaveBeenCalled();
  });

  it("still asks it of a user who may read scopes", async () => {
    signInAs(WITH_READS);
    const scopes = vi.fn(() => Promise.resolve([]));
    answer("dhcpApi", "listScopesBySubnet", scopes);
    answer("ipamApi", "listAddresses", () => Promise.resolve([]));
    await open(<SubnetDetail subnet={SUBNET} onSubnetEdited={() => {}} />);
    await waitFor(() => expect(scopes).toHaveBeenCalledWith("sub-1"));
  });
});
