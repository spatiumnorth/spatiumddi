/**
 * @vitest-environment jsdom
 *
 * DNS Edit Server, TSIG key metadata, DNS pool, zone dynamic-update ACL, DHCP
 * phone profile and DHCP device policy read the object fresh on open and send
 * only what the operator changed (#3379), the #3365 pattern. Each is handed a
 * stale row (or a stale cached read) while the API holds the newer one: an
 * other-field Save must not write the stale value back, and a set replaced
 * wholesale (pool members, the ACL, phone scopes) must keep an entry that was
 * added elsewhere.
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
  DHCPDevicePolicy,
  DNSPool,
  DNSServer,
  DNSServerGroup,
  DNSTSIGKey,
  DNSZone,
  PhoneProfile,
  ZoneUpdateAcl,
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

const { ServerModal, TSIGKeyModal } = await import("@/pages/dns/DNSPage");
const { PoolModal } = await import("@/pages/dns/PoolsView");
const { DynamicUpdateAclModal } =
  await import("@/pages/dns/DynamicUpdateAclModal");
const { PhoneProfileEditorModal } =
  await import("@/pages/dhcp/PhoneProfilesTab");
const { DevicePolicyModal } = await import("@/pages/dhcp/DevicePoliciesTab");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode, client?: QueryClient) {
  const qc =
    client ??
    new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const save = (name = /^Save/) =>
  fireEvent.click(screen.getByRole("button", { name }));

describe("Edit DNS server (#3379)", () => {
  const stale = {
    id: "s-1",
    group_id: "g-1",
    name: "ns1",
    driver: "bind9",
    host: "10.0.0.1",
    port: 53,
    api_port: null,
    roles: [],
    notes: "n",
    is_enabled: true,
    is_primary: false,
    has_credentials: false,
  } as unknown as DNSServer;
  const fresh = { ...stale, host: "10.0.0.9" } as DNSServer;

  it("shows the stored host and sends only the changed notes", async () => {
    const updateServer = vi.fn(() => Promise.resolve(fresh));
    answers.dnsApi = {
      listServers: () => Promise.resolve([fresh]),
      listGroups: () => Promise.resolve([]),
      updateServer,
    };
    open(<ServerModal groupId="g-1" server={stale} onClose={() => {}} />);
    const notes = await screen.findByDisplayValue("n");
    expect(screen.getByDisplayValue("10.0.0.9")).toBeTruthy();
    fireEvent.change(notes, { target: { value: "new" } });
    save();
    await waitFor(() => expect(updateServer).toHaveBeenCalled());
    expect(updateServer).toHaveBeenCalledWith("g-1", "s-1", { notes: "new" });
  });

  it("an untouched Save sends nothing and closes", async () => {
    const updateServer = vi.fn(() => Promise.resolve(fresh));
    const onClose = vi.fn();
    answers.dnsApi = {
      listServers: () => Promise.resolve([fresh]),
      listGroups: () => Promise.resolve([]),
      updateServer,
    };
    open(<ServerModal groupId="g-1" server={stale} onClose={onClose} />);
    await screen.findByDisplayValue("n");
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateServer).not.toHaveBeenCalled();
  });

  it("a server deleted meanwhile shows the error, not the stale form", async () => {
    answers.dnsApi = { listServers: () => Promise.resolve([]) };
    open(<ServerModal groupId="g-1" server={stale} onClose={() => {}} />);
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByDisplayValue("10.0.0.1")).toBeNull();
  });
});

describe("Edit TSIG key metadata (#3379)", () => {
  const stale = {
    id: "k-1",
    name: "key.",
    algorithm: "hmac-sha256",
    purpose: "nsupdate",
    notes: "n",
  } as unknown as DNSTSIGKey;
  const fresh = { ...stale, purpose: "axfr-pull" } as DNSTSIGKey;

  it("shows the stored purpose and sends only the changed notes", async () => {
    const updateTSIGKey = vi.fn(() => Promise.resolve(fresh));
    answers.dnsApi = {
      listTSIGKeys: () => Promise.resolve([fresh]),
      updateTSIGKey,
    };
    open(<TSIGKeyModal groupId="g-1" existing={stale} onClose={() => {}} />);
    const notes = await screen.findByDisplayValue("n");
    expect(screen.getByDisplayValue("axfr-pull")).toBeTruthy();
    fireEvent.change(notes, { target: { value: "new" } });
    save();
    await waitFor(() => expect(updateTSIGKey).toHaveBeenCalled());
    expect(updateTSIGKey).toHaveBeenCalledWith("g-1", "k-1", { notes: "new" });
  });

  it("an untouched Save sends nothing", async () => {
    const updateTSIGKey = vi.fn(() => Promise.resolve(fresh));
    const onClose = vi.fn();
    answers.dnsApi = {
      listTSIGKeys: () => Promise.resolve([fresh]),
      updateTSIGKey,
    };
    open(<TSIGKeyModal groupId="g-1" existing={stale} onClose={onClose} />);
    await screen.findByDisplayValue("n");
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateTSIGKey).not.toHaveBeenCalled();
  });
});

describe("Edit DNS pool (#3379)", () => {
  const member = (id: string, address: string) => ({
    id,
    pool_id: "p-1",
    address,
    weight: 1,
    enabled: true,
    serving_cidrs: [],
    site_id: null,
    last_check_state: "unknown",
  });
  const stale = {
    id: "p-1",
    name: "web",
    description: "d",
    record_name: "www",
    record_type: "A",
    ttl: 30,
    enabled: true,
    hc_type: "tcp",
    hc_target_port: 80,
    hc_path: "/",
    hc_method: "GET",
    hc_verify_tls: false,
    hc_expected_status_codes: [200],
    hc_interval_seconds: 30,
    hc_timeout_seconds: 5,
    hc_unhealthy_threshold: 2,
    hc_healthy_threshold: 2,
    members: [member("m-1", "10.0.0.1")],
  } as unknown as DNSPool;
  const fresh = {
    ...stale,
    ttl: 60,
    members: [member("m-1", "10.0.0.1"), member("m-2", "10.0.0.2")],
  } as unknown as DNSPool;

  it("keeps a member added elsewhere and sends only the changed description", async () => {
    const updatePool = vi.fn(() => Promise.resolve(fresh));
    const deletePoolMember = vi.fn(() => Promise.resolve());
    const updatePoolMember = vi.fn(() => Promise.resolve());
    const addPoolMember = vi.fn(() => Promise.resolve());
    answers.dnsApi = {
      getPool: () => Promise.resolve(fresh),
      updatePool,
      deletePoolMember,
      updatePoolMember,
      addPoolMember,
    };
    answers.sitesApi = { list: () => Promise.resolve({ items: [] }) };
    open(
      <PoolModal
        group={{ id: "g-1" } as DNSServerGroup}
        zone={{ id: "z-1" } as DNSZone}
        pool={stale}
        onClose={() => {}}
      />,
    );
    const desc = await screen.findByDisplayValue("d");
    expect(screen.getByDisplayValue("60")).toBeTruthy();
    expect(screen.getByDisplayValue("10.0.0.2")).toBeTruthy();
    fireEvent.change(desc, { target: { value: "new" } });
    save();
    await waitFor(() => expect(updatePool).toHaveBeenCalled());
    expect(updatePool).toHaveBeenCalledWith("p-1", { description: "new" });
    expect(deletePoolMember).not.toHaveBeenCalled();
    expect(updatePoolMember).not.toHaveBeenCalled();
    expect(addPoolMember).not.toHaveBeenCalled();
  });

  it("an untouched Save sends nothing", async () => {
    const updatePool = vi.fn(() => Promise.resolve(fresh));
    const deletePoolMember = vi.fn(() => Promise.resolve());
    const onClose = vi.fn();
    answers.dnsApi = {
      getPool: () => Promise.resolve(fresh),
      updatePool,
      deletePoolMember,
    };
    answers.sitesApi = { list: () => Promise.resolve({ items: [] }) };
    open(
      <PoolModal
        group={{ id: "g-1" } as DNSServerGroup}
        zone={{ id: "z-1" } as DNSZone}
        pool={stale}
        onClose={onClose}
      />,
    );
    await screen.findByDisplayValue("d");
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updatePool).not.toHaveBeenCalled();
    expect(deletePoolMember).not.toHaveBeenCalled();
  });
});

describe("Zone dynamic-updates ACL (#3379)", () => {
  const entry = (id: string, cidr: string) => ({
    id,
    seq: 0,
    action: "grant",
    match_kind: "ip",
    ip_cidr: cidr,
    tsig_key_id: null,
    tsig_key_name: null,
    name_scope: null,
    name_pattern: null,
    record_types: null,
  });
  const caps = {
    supports_ip_acl: true,
    supports_tsig_acl: true,
    supports_name_scoping: false,
    supports_per_type: false,
    coarse_enum_only: true,
    supported: true,
  };
  const acl = (entries: unknown[], enabled: boolean) =>
    ({
      zone_id: "z-1",
      dynamic_update_enabled: enabled,
      driver_names: ["bind9"],
      caps,
      entries,
      warnings: [],
    }) as unknown as ZoneUpdateAcl;
  const cached = acl([entry("e-1", "10.0.0.0/24")], false);
  const fresh = acl(
    [entry("e-1", "10.0.0.0/24"), entry("e-2", "192.168.1.0/24")],
    false,
  );

  function primedClient() {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    // The 30 s-stale read an older dialog seeded itself from.
    qc.setQueryData(["dns-zone-update-acl", "g-1", "z-1"], cached);
    return qc;
  }

  it("keeps an entry added elsewhere when the toggle is saved", async () => {
    const replaceZoneUpdateAcl = vi.fn(() => Promise.resolve(fresh));
    answers.dnsApi = {
      getZoneUpdateAcl: () => Promise.resolve(fresh),
      replaceZoneUpdateAcl,
      listTSIGKeys: () => Promise.resolve([]),
    };
    open(
      <DynamicUpdateAclModal
        groupId="g-1"
        zoneId="z-1"
        zoneName="example.com."
        onClose={() => {}}
      />,
      primedClient(),
    );
    expect(await screen.findByDisplayValue("192.168.1.0/24")).toBeTruthy();
    fireEvent.click(screen.getByRole("checkbox"));
    save(/^Save ACL/);
    await waitFor(() => expect(replaceZoneUpdateAcl).toHaveBeenCalled());
    const [, , body] = replaceZoneUpdateAcl.mock.calls[0] as unknown as [
      string,
      string,
      { dynamic_update_enabled: boolean; entries: { ip_cidr: string }[] },
    ];
    expect(body.dynamic_update_enabled).toBe(true);
    expect(body.entries.map((e) => e.ip_cidr)).toEqual([
      "10.0.0.0/24",
      "192.168.1.0/24",
    ]);
  });

  it("an untouched Save sends nothing and closes", async () => {
    const replaceZoneUpdateAcl = vi.fn(() => Promise.resolve(fresh));
    const onClose = vi.fn();
    answers.dnsApi = {
      getZoneUpdateAcl: () => Promise.resolve(fresh),
      replaceZoneUpdateAcl,
      listTSIGKeys: () => Promise.resolve([]),
    };
    open(
      <DynamicUpdateAclModal
        groupId="g-1"
        zoneId="z-1"
        zoneName="example.com."
        onClose={onClose}
      />,
      primedClient(),
    );
    await screen.findByDisplayValue("192.168.1.0/24");
    save(/^Save ACL/);
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(replaceZoneUpdateAcl).not.toHaveBeenCalled();
  });

  it("a failed read shows the error, not the cached ACL", async () => {
    answers.dnsApi = {
      getZoneUpdateAcl: () => Promise.reject(new Error("boom")),
      listTSIGKeys: () => Promise.resolve([]),
    };
    open(
      <DynamicUpdateAclModal
        groupId="g-1"
        zoneId="z-1"
        zoneName="example.com."
        onClose={() => {}}
      />,
      primedClient(),
    );
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByDisplayValue("10.0.0.0/24")).toBeNull();
  });
});

describe("Edit DHCP phone profile (#3379)", () => {
  const stale = {
    id: "pp-1",
    group_id: "g-1",
    name: "Cisco",
    description: "d",
    enabled: true,
    vendor: null,
    vendor_class_match: "Cisco",
    option_set: [],
    scope_ids: ["sc-1"],
  } as unknown as PhoneProfile;
  const fresh = {
    ...stale,
    vendor_class_match: "Cisco-new",
    scope_ids: ["sc-1", "sc-2"],
  } as PhoneProfile;
  const scopes = [
    { id: "sc-1", name: "scope-one", subnet_id: "n-1" },
    { id: "sc-2", name: "scope-two", subnet_id: "n-2" },
  ];

  function wire(onUpdate: () => unknown, onScopes: () => unknown) {
    answers.dhcpApi = {
      listPhoneProfiles: () => Promise.resolve([fresh]),
      listVoipVendors: () => Promise.resolve([]),
      listScopesByGroup: () => Promise.resolve(scopes),
      updatePhoneProfile: onUpdate,
      setPhoneProfileScopes: onScopes,
    };
    answers.ipamApi = { listSubnets: () => Promise.resolve([]) };
  }

  it("sends only the changed description and leaves the scope set alone", async () => {
    const update = vi.fn(() => Promise.resolve(fresh));
    const setScopes = vi.fn(() => Promise.resolve(fresh));
    wire(update, setScopes);
    open(
      <PhoneProfileEditorModal
        groupId="g-1"
        profile={stale}
        onClose={() => {}}
      />,
    );
    const desc = await screen.findByDisplayValue("d");
    expect(screen.getByDisplayValue("Cisco-new")).toBeTruthy();
    fireEvent.change(desc, { target: { value: "new" } });
    save();
    await waitFor(() => expect(update).toHaveBeenCalled());
    expect(update).toHaveBeenCalledWith("pp-1", { description: "new" });
    expect(setScopes).not.toHaveBeenCalled();
  });

  it("replaces scopes from the fresh set, keeping one attached elsewhere", async () => {
    const update = vi.fn(() => Promise.resolve(fresh));
    const setScopes = vi.fn(() => Promise.resolve(fresh));
    wire(update, setScopes);
    open(
      <PhoneProfileEditorModal
        groupId="g-1"
        profile={stale}
        onClose={() => {}}
      />,
    );
    await screen.findByDisplayValue("d");
    // sc-2 was attached elsewhere; the operator detaches sc-1 only.
    await screen.findByText("scope-two");
    const one = screen
      .getByText("scope-one")
      .parentElement!.querySelector("input") as HTMLInputElement;
    expect(
      (
        screen
          .getByText("scope-two")
          .parentElement!.querySelector("input") as HTMLInputElement
      ).checked,
    ).toBe(true);
    fireEvent.click(one);
    save();
    await waitFor(() => expect(setScopes).toHaveBeenCalled());
    expect(setScopes).toHaveBeenCalledWith("pp-1", ["sc-2"]);
    expect(update).not.toHaveBeenCalled();
  });

  it("an untouched Save sends nothing", async () => {
    const update = vi.fn(() => Promise.resolve(fresh));
    const setScopes = vi.fn(() => Promise.resolve(fresh));
    const onClose = vi.fn();
    wire(update, setScopes);
    open(
      <PhoneProfileEditorModal
        groupId="g-1"
        profile={stale}
        onClose={onClose}
      />,
    );
    await screen.findByDisplayValue("d");
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(update).not.toHaveBeenCalled();
    expect(setScopes).not.toHaveBeenCalled();
  });
});

describe("Edit DHCP device policy (#3379)", () => {
  const stale = {
    id: "dp-1",
    group_id: "g-1",
    name: "IoT",
    description: "d",
    enabled: true,
    class_name: "x",
    device_classes: ["Generic IoT"],
    options: {},
    lease_time: null,
    match_override: null,
    include_ambiguous: false,
    priority: 0,
  } as unknown as DHCPDevicePolicy;
  const fresh = { ...stale, lease_time: 600 } as DHCPDevicePolicy;

  it("shows the stored lease time and sends only the changed description", async () => {
    const updateDevicePolicy = vi.fn(() => Promise.resolve(fresh));
    answers.dhcpApi = {
      listDevicePolicies: () => Promise.resolve([fresh]),
      listDeviceObservations: () => Promise.resolve({ classes: [] }),
      updateDevicePolicy,
    };
    open(<DevicePolicyModal groupId="g-1" policy={stale} onClose={() => {}} />);
    const desc = await screen.findByDisplayValue("d");
    expect(screen.getByDisplayValue("600")).toBeTruthy();
    fireEvent.change(desc, { target: { value: "new" } });
    save();
    await waitFor(() => expect(updateDevicePolicy).toHaveBeenCalled());
    expect(updateDevicePolicy).toHaveBeenCalledWith("dp-1", {
      description: "new",
    });
  });

  it("an untouched Save sends nothing and closes", async () => {
    const updateDevicePolicy = vi.fn(() => Promise.resolve(fresh));
    const onClose = vi.fn();
    answers.dhcpApi = {
      listDevicePolicies: () => Promise.resolve([fresh]),
      listDeviceObservations: () => Promise.resolve({ classes: [] }),
      updateDevicePolicy,
    };
    open(<DevicePolicyModal groupId="g-1" policy={stale} onClose={onClose} />);
    await screen.findByDisplayValue("d");
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateDevicePolicy).not.toHaveBeenCalled();
  });

  it("a failed read shows the error, not the stale form", async () => {
    answers.dhcpApi = {
      listDevicePolicies: () => Promise.reject(new Error("boom")),
    };
    open(<DevicePolicyModal groupId="g-1" policy={stale} onClose={() => {}} />);
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByDisplayValue("IoT")).toBeNull();
  });
});
