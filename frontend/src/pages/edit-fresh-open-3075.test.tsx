/**
 * @vitest-environment jsdom
 *
 * Edit dialogs read their row fresh when they open, and an untouched Save
 * sends nothing that reverts another surface's change (#3075, #3076, #3077).
 *
 * Each dialog is handed a stale row (what the page cached) while the API
 * holds the newer value; the dialog must show the newer value, and Save must
 * send only what the operator touched.
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
  DHCPScope,
  DHCPStaticAssignment,
  DNSRecord,
  IPSpace,
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

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { EditSpaceModal } = await import("@/pages/ipam/IPAMPage");
const { CreateStaticAssignmentModal } =
  await import("@/pages/dhcp/CreateStaticAssignmentModal");
const { CreateScopeModal } = await import("@/pages/dhcp/CreateScopeModal");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode, qc?: QueryClient) {
  const client =
    qc ?? new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

const save = () =>
  fireEvent.click(screen.getByRole("button", { name: /^Save/ }));

describe("Edit IP Space (#3075)", () => {
  const stale = { id: "sp-1", name: "lab", description: "xp d1" } as IPSpace;
  const fresh = { ...stale, description: "xp d2" } as IPSpace;

  it("shows the stored description and an untouched Save sends nothing", async () => {
    const updateSpace = vi.fn(() => Promise.resolve(fresh));
    answers.ipamApi = { getSpace: () => Promise.resolve(fresh), updateSpace };
    const onClose = vi.fn();
    open(
      <EditSpaceModal space={stale} onClose={onClose} onDeleted={() => {}} />,
    );
    const box = await screen.findByDisplayValue("xp d2");
    expect(box).toBeTruthy();
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateSpace).not.toHaveBeenCalled();
  });

  it("sends only the field the operator changed", async () => {
    const updateSpace = vi.fn(() => Promise.resolve(fresh));
    answers.ipamApi = { getSpace: () => Promise.resolve(fresh), updateSpace };
    open(
      <EditSpaceModal space={stale} onClose={() => {}} onDeleted={() => {}} />,
    );
    const box = await screen.findByDisplayValue("xp d2");
    fireEvent.change(box, { target: { value: "xp d3" } });
    save();
    await waitFor(() => expect(updateSpace).toHaveBeenCalled());
    expect(updateSpace).toHaveBeenCalledWith("sp-1", { description: "xp d3" });
  });
});

describe("Edit Static Assignment (#3076)", () => {
  const scope = { id: "sc-1", subnet_id: "sn-1" } as DHCPScope;
  const row = (hostname: string) =>
    ({
      id: "st-1",
      scope_id: "sc-1",
      mac_address: "02:98:14:00:00:20",
      ip_address: "10.98.140.20",
      hostname,
      description: "",
      client_id: null,
    }) as unknown as DHCPStaticAssignment;

  function setup() {
    const updateStatic = vi.fn(() => Promise.resolve(row("x")));
    answers.dhcpApi = {
      listStatics: () => Promise.resolve([row("xp-st-b")]),
      listPools: () => Promise.resolve([]),
      updateStatic,
    };
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    qc.setQueryDefaults(["dhcp-statics"], {
      queryFn: () => answers.dhcpApi.listStatics(),
    });
    qc.setQueryData(["dhcp-statics", "sc-1"], [row("xp-st-a")]);
    return { qc, updateStatic };
  }

  it("shows the hostname an inline IPAM edit stored; an untouched Save sends nothing", async () => {
    const { qc, updateStatic } = setup();
    const onClose = vi.fn();
    open(
      <CreateStaticAssignmentModal
        scope={scope}
        staticAssignment={row("xp-st-a")}
        onClose={onClose}
      />,
      qc,
    );
    await screen.findByDisplayValue("xp-st-b");
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateStatic).not.toHaveBeenCalled();
  });

  it("sends only the changed field", async () => {
    const { qc, updateStatic } = setup();
    open(
      <CreateStaticAssignmentModal
        scope={scope}
        staticAssignment={row("xp-st-a")}
        onClose={() => {}}
      />,
      qc,
    );
    const box = await screen.findByDisplayValue("xp-st-b");
    fireEvent.change(box, { target: { value: "xp-st-c" } });
    save();
    await waitFor(() => expect(updateStatic).toHaveBeenCalled());
    expect(updateStatic).toHaveBeenCalledWith("sc-1", "st-1", {
      hostname: "xp-st-c",
    });
  });
});

describe("Edit DHCP Scope (#3077)", () => {
  it("shows the stored Lease Time, not the cached one", async () => {
    const stale = {
      id: "sc-1",
      subnet_id: "sn-1",
      group_id: "g-1",
      name: "s",
      lease_time: 3600,
      address_family: "ipv4",
      options: [],
      relay_addresses: [],
    } as unknown as DHCPScope;
    answers.dhcpApi = {
      getScope: () => Promise.resolve({ ...stale, lease_time: 7200 }),
    };
    open(<CreateScopeModal scope={stale} onClose={() => {}} />);
    await screen.findByDisplayValue("7200");
    expect(screen.queryByDisplayValue("3600")).toBeNull();
  });
});

describe("Edit Record (#3077)", () => {
  it("shows the stored value and an untouched Save sends nothing", async () => {
    const rec = (value: string) =>
      ({
        id: "r-1",
        zone_id: "z-1",
        view_id: null,
        name: "www",
        record_type: "A",
        value,
        ttl: 300,
        priority: null,
        weight: null,
        port: null,
      }) as unknown as DNSRecord;
    const updateRecord = vi.fn(() => Promise.resolve(rec("x")));
    answers.dnsApi = {
      listRecords: () =>
        Promise.resolve({ items: [rec("10.98.200.11")], total: 1 }),
      listViews: () => Promise.resolve([]),
      updateRecord,
    };
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    qc.setQueryDefaults(["dns-records"], {
      queryFn: () => answers.dnsApi.listRecords(),
    });
    qc.setQueryData(["dns-records", "z-1", {}], {
      items: [rec("10.98.200.10")],
      total: 1,
    });
    const { RecordModal } = await import("@/pages/dns/DNSPage");
    const onClose = vi.fn();
    open(
      <RecordModal
        groupId="g-1"
        zoneId="z-1"
        zoneName="example.com."
        record={rec("10.98.200.10")}
        onClose={onClose}
      />,
      qc,
    );
    await screen.findByDisplayValue("10.98.200.11");
    save();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateRecord).not.toHaveBeenCalled();
  });
});
