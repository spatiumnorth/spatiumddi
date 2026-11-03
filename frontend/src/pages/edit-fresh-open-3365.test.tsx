/**
 * @vitest-environment jsdom
 *
 * Edit Server Group (DNS), Edit Blocking List, Edit MAC Block, Edit PXE
 * profile and Edit address set read the object fresh on open and send only
 * what the operator changed (#3365). Each is handed a stale row while the API
 * holds the newer one: an untouched/other-field Save must not write the stale
 * value back.
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
import type {
  AddressSet,
  DNSSECPolicy,
  NATMapping,
  DHCPMACBlock,
  DNSBlockList,
  DNSServerGroup,
  PXEProfile,
} from "@/lib/api";

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

const { GroupModal, BlocklistModal } = await import("@/pages/dns/DNSPage");
const { MacBlockModal } = await import("@/pages/dhcp/MacBlocksTab");
const { ProfileEditor } = await import("@/pages/dhcp/PXEProfilesPage");
const { AddressSetModal } = await import("@/pages/ipam/IPAMPage");
const { PolicyModal } = await import("@/pages/dns/DNSSECPoliciesPage");
const { NATMappingModal } = await import("@/pages/ipam/NATPage");

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

describe("Edit Server Group (#3365)", () => {
  const stale = {
    id: "g-1",
    name: "grp",
    description: "d",
    group_type: "internal",
    is_recursive: true,
    catalog_zones_enabled: false,
    catalog_zone_name: "catalog.spatium.invalid.",
    is_public_facing: false,
    auto_reverse_zones_at_provider: false,
  } as unknown as DNSServerGroup;
  const fresh = { ...stale, is_recursive: false } as DNSServerGroup;

  it("shows the stored recursion and sends only the changed description", async () => {
    const updateGroup = vi.fn(() => Promise.resolve(fresh));
    answers.dnsApi = { getGroup: () => Promise.resolve(fresh), updateGroup };
    open(<GroupModal group={stale} onClose={() => {}} />);
    const desc = await screen.findByDisplayValue("d");
    expect(
      (screen.getByLabelText(/Allow recursion/) as HTMLInputElement).checked,
    ).toBe(false);
    fireEvent.change(desc, { target: { value: "new" } });
    save();
    await waitFor(() => expect(updateGroup).toHaveBeenCalled());
    expect(updateGroup).toHaveBeenCalledWith("g-1", { description: "new" });
  });
});

describe("Edit Blocking List (#3365)", () => {
  const stale = {
    id: "b-1",
    name: "bl",
    description: "d",
    category: "custom",
    source_type: "manual",
    feed_url: null,
    feed_format: "hosts",
    block_mode: "nxdomain",
    sinkhole_ip: null,
    update_interval_hours: 24,
    feed_entries_are_wildcard: true,
    enabled: true,
  } as unknown as DNSBlockList;
  const fresh = { ...stale, category: "xp-other" } as DNSBlockList;

  it("shows the stored category and sends only the changed description", async () => {
    const update = vi.fn(() => Promise.resolve(fresh));
    answers.dnsBlocklistApi = { get: () => Promise.resolve(fresh), update };
    open(<BlocklistModal list={stale} onClose={() => {}} />);
    const desc = await screen.findByDisplayValue("d");
    expect(screen.getByDisplayValue("xp-other")).toBeTruthy();
    fireEvent.change(desc, { target: { value: "new" } });
    save();
    await waitFor(() => expect(update).toHaveBeenCalled());
    expect(update).toHaveBeenCalledWith("b-1", { description: "new" });
  });
});

describe("Edit MAC Block (#3365)", () => {
  const stale = {
    id: "m-1",
    group_id: "g-1",
    mac_address: "aa:bb:cc:dd:ee:ff",
    reason: "other",
    description: "d",
    enabled: true,
    expires_at: null,
  } as unknown as DHCPMACBlock;
  const fresh = { ...stale, enabled: false } as DHCPMACBlock;

  it("shows the stored enabled flag and sends only the changed description", async () => {
    const updateMacBlock = vi.fn(() => Promise.resolve(fresh));
    answers.dhcpApi = {
      listMacBlocks: () => Promise.resolve([fresh]),
      updateMacBlock,
    };
    open(<MacBlockModal groupId="g-1" block={stale} onClose={() => {}} />);
    const desc = await screen.findByDisplayValue("d");
    fireEvent.change(desc, { target: { value: "new" } });
    save();
    await waitFor(() => expect(updateMacBlock).toHaveBeenCalled());
    expect(updateMacBlock).toHaveBeenCalledWith("g-1", "m-1", {
      description: "new",
    });
  });
});

describe("Edit PXE profile (#3365)", () => {
  const rule = (priority: number, file: string) => ({
    id: `r-${priority}`,
    priority,
    match_kind: "first_stage",
    vendor_class_match: "PXEClient",
    arch_codes: [0],
    boot_filename: file,
    boot_file_url_v6: null,
  });
  const stale = {
    id: "p-1",
    group_id: "g-1",
    name: "prof",
    description: "d",
    next_server: "10.0.0.1",
    enabled: true,
    matches: [rule(10, "a"), rule(20, "b")],
  } as unknown as PXEProfile;
  const fresh = {
    ...stale,
    matches: [...stale.matches, rule(30, "c")],
  } as PXEProfile;

  it("shows the third rule; an untouched-rules Save leaves the rules out", async () => {
    const updatePxeProfile = vi.fn(() => Promise.resolve(fresh));
    answers.dhcpApi = {
      getPxeProfile: () => Promise.resolve(fresh),
      updatePxeProfile,
    };
    open(
      <ProfileEditor
        mode="edit"
        groupId="g-1"
        existing={stale}
        onClose={() => {}}
        onSaved={() => {}}
      />,
    );
    const desc = await screen.findByDisplayValue("d");
    expect(screen.getByDisplayValue("c")).toBeTruthy();
    fireEvent.change(desc, { target: { value: "new" } });
    save();
    await waitFor(() => expect(updatePxeProfile).toHaveBeenCalled());
    expect(updatePxeProfile).toHaveBeenCalledWith("p-1", {
      description: "new",
    });
  });
});

describe("Edit address set (#3365)", () => {
  const stale = {
    id: "s-1",
    name: "set",
    description: "d",
    subnet_id: "sn-1",
    customer_id: null,
    site_id: null,
    range_kind: "contiguous",
    start_address: "10.0.0.10",
    end_address: "10.0.0.99",
    explicit_addresses: [],
  } as unknown as AddressSet;
  const fresh = { ...stale, end_address: "10.0.0.79" } as AddressSet;

  it("shows the stored end address and sends only the changed description", async () => {
    const update = vi.fn(() => Promise.resolve(fresh));
    answers.addressSetsApi = { get: () => Promise.resolve(fresh), update };
    open(
      <AddressSetModal
        subnet={{ id: "sn-1", network: "10.0.0.0/24" } as never}
        existing={stale}
        onClose={() => {}}
        onSaved={() => {}}
      />,
    );
    const desc = await screen.findByDisplayValue("d");
    expect(screen.getByDisplayValue("10.0.0.79")).toBeTruthy();
    fireEvent.change(desc, { target: { value: "new" } });
    fireEvent.click(screen.getByRole("button", { name: /^Save/ }));
    await waitFor(() => expect(update).toHaveBeenCalled());
    expect(update).toHaveBeenCalledWith("s-1", { description: "new" });
  });
});

describe("Edit DNSSEC policy (#3365)", () => {
  const stale = {
    id: "dp-1",
    name: "pol",
    description: "d",
    is_builtin: false,
    algorithm: "ecdsap256sha256",
    ksk_lifetime_days: 0,
    zsk_lifetime_days: 90,
    nsec3: false,
    nsec3_iterations: 0,
    nsec3_salt_length: 0,
    nsec3_optout: false,
  } as unknown as DNSSECPolicy;
  const fresh = { ...stale, zsk_lifetime_days: 120 } as DNSSECPolicy;

  it("shows the stored lifetime and sends only the changed description", async () => {
    const updateDnssecPolicy = vi.fn(() => Promise.resolve(fresh));
    answers.dnsApi = {
      listDnssecPolicies: () => Promise.resolve([fresh]),
      updateDnssecPolicy,
    };
    open(<PolicyModal existing={stale} onClose={() => {}} />);
    const desc = await screen.findByDisplayValue("d");
    expect(screen.getByDisplayValue("120")).toBeTruthy();
    fireEvent.change(desc, { target: { value: "new" } });
    save();
    await waitFor(() => expect(updateDnssecPolicy).toHaveBeenCalled());
    expect(updateDnssecPolicy).toHaveBeenCalledWith("dp-1", {
      description: "new",
    });
  });
});

describe("Edit NAT mapping (#3365)", () => {
  const stale = {
    id: "n-1",
    name: "nat",
    kind: "1to1",
    internal_ip: "10.0.0.5",
    internal_subnet_id: null,
    internal_port_start: null,
    internal_port_end: null,
    external_ip: "203.0.113.5",
    external_port_start: null,
    external_port_end: null,
    protocol: "any",
    device_label: null,
    description: "d",
  } as unknown as NATMapping;
  const fresh = { ...stale, external_ip: "203.0.113.9" } as NATMapping;

  it("shows the stored external IP and sends only the changed description", async () => {
    const update = vi.fn(() => Promise.resolve(fresh));
    answers.natApi = { get: () => Promise.resolve(fresh), update };
    open(
      <NATMappingModal initial={stale} onClose={() => {}} onSaved={() => {}} />,
    );
    const desc = await screen.findByDisplayValue("d");
    expect(screen.getByDisplayValue("203.0.113.9")).toBeTruthy();
    fireEvent.change(desc, { target: { value: "new" } });
    save();
    await waitFor(() => expect(update).toHaveBeenCalled());
    expect(update).toHaveBeenCalledWith("n-1", { description: "new" });
  });
});
