/**
 * @vitest-environment jsdom
 *
 * The IPAM "Scan with nmap" entry points are offered only to a role that can
 * both start a scan (write on 'manage_nmap_scans') and read it back (read),
 * since the viewer the UI opens next asks read (#3279). A write-only role is
 * shown each entry disabled with the reason. With the `tools.nmap` module
 * off the server refuses every scan route, so no entry is offered at all,
 * whatever the grants. Real `usePermissions`.
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
import type { IPAddress, Subnet } from "@/lib/api";

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

// Module ids switched off for the current case; everything else is on.
const modulesOff = new Set<string>();

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: (id: string) => !modulesOff.has(id),
  }),
}));

const { SubnetDetail, EditAddressModal } = await import("./IPAMPage");
const { IPDetailModal } = await import("./IPDetailModal");

afterEach(() => {
  cleanup();
  modulesOff.clear();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-10-22T00:00:00Z";

type Grants = [string, string][] | "superadmin" | "loading";

// Resolves once the permission set has been served, so a "disabled" verdict
// is the gate's answer and not just the fail-closed loading state.
let served: Promise<void> = Promise.resolve();

function signInAs(grants: Grants) {
  let markServed = () => {};
  served = new Promise((r) => (markServed = r));
  answers.authApi = {
    myPermissions: () => {
      if (grants === "loading") return new Promise(() => {});
      markServed();
      return Promise.resolve(
        grants === "superadmin"
          ? { is_superadmin: true, grants: [] }
          : {
              is_superadmin: false,
              grants: grants.map(([action, resource_type]) => ({
                action,
                resource_type,
                resource_id: null,
              })),
            },
      );
    },
  };
}

// Enough to open each surface; none of these grants reaches nmap.
const IPAM_ADMIN: [string, string][] = [
  ["admin", "ip_space"],
  ["admin", "ip_block"],
  ["admin", "subnet"],
  ["admin", "ip_address"],
];
const WRITE_ONLY: [string, string][] = [
  ...IPAM_ADMIN,
  ["write", "manage_nmap_scans"],
];
const WRITE_READ: [string, string][] = [
  ...WRITE_ONLY,
  ["read", "manage_nmap_scans"],
];
const REASON = /read permission on nmap scans/;

async function mount(ui: ReactNode) {
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

const ADDR = {
  id: "a1",
  subnet_id: "sub-1",
  address: "10.1.0.10",
  status: "allocated",
  role: null,
  hostname: "h",
  fqdn: null,
  description: "",
  mac_address: null,
  tags: {},
  custom_fields: {},
  created_at: STAMP,
  modified_at: STAMP,
} as unknown as IPAddress;

async function subnetScanItem(grants: Grants) {
  signInAs(grants);
  answers.ipamApi = { listAddresses: () => Promise.resolve([]) };
  await mount(<SubnetDetail subnet={SUBNET} onSubnetEdited={() => {}} />);
  fireEvent.click(screen.getByRole("button", { name: /Tools/ }));
  const found = await screen.findAllByText("Scan with nmap");
  return found[0].closest("button") as HTMLButtonElement;
}

async function detailScanButton(grants: Grants) {
  signInAs(grants);
  await mount(
    <IPDetailModal
      address={ADDR}
      canEdit={false}
      onClose={() => {}}
      onEdit={() => {}}
      onScan={() => {}}
    />,
  );
  return screen.getByRole("button", {
    name: /Scan with Nmap/,
  }) as HTMLButtonElement;
}

async function editScanButton(grants: Grants) {
  signInAs(grants);
  answers.ipamApi = { getAddress: () => Promise.resolve(ADDR) };
  answers.customFieldsApi = { list: () => Promise.resolve([]) };
  await mount(<EditAddressModal address={ADDR} onClose={() => {}} />);
  return (await screen.findByRole("button", {
    name: /Scan with Nmap/,
  })) as HTMLButtonElement;
}

const ENTRIES: [string, (g: Grants) => Promise<HTMLButtonElement>][] = [
  ["subnet Tools > Scan with nmap", subnetScanItem],
  ["IP detail Scan with Nmap", detailScanButton],
  ["Edit address Scan with Nmap", editScanButton],
];

// Same three surfaces, asserting absence (the helpers above throw/time out
// when the control is missing, so these query directly).
const ABSENT: [string, (g: Grants) => Promise<boolean>][] = [
  [
    "subnet Tools > Scan with nmap",
    async (g) => {
      signInAs(g);
      answers.ipamApi = { listAddresses: () => Promise.resolve([]) };
      await mount(<SubnetDetail subnet={SUBNET} onSubnetEdited={() => {}} />);
      fireEvent.click(screen.getByRole("button", { name: /Tools/ }));
      await screen.findByText("Split…");
      return screen.queryAllByText("Scan with nmap").length === 0;
    },
  ],
  [
    "IP detail Scan with Nmap",
    async (g) => {
      signInAs(g);
      await mount(
        <IPDetailModal
          address={ADDR}
          canEdit={false}
          onClose={() => {}}
          onEdit={() => {}}
          onScan={() => {}}
        />,
      );
      return (
        screen.queryAllByRole("button", { name: /Scan with Nmap/ }).length === 0
      );
    },
  ],
  [
    "Edit address Scan with Nmap",
    async (g) => {
      signInAs(g);
      answers.ipamApi = { getAddress: () => Promise.resolve(ADDR) };
      answers.customFieldsApi = { list: () => Promise.resolve([]) };
      await mount(<EditAddressModal address={ADDR} onClose={() => {}} />);
      await screen.findByRole("button", { name: /Network/ });
      return (
        screen.queryAllByRole("button", { name: /Scan with Nmap/ }).length === 0
      );
    },
  ],
];

describe.each(ABSENT)("%s with tools.nmap off (#3279)", (_name, absent) => {
  it("is not offered to a role holding write and read", async () => {
    modulesOff.add("tools.nmap");
    expect(await absent(WRITE_READ)).toBe(true);
  });

  it("is not offered to a superadmin", async () => {
    modulesOff.add("tools.nmap");
    expect(await absent("superadmin")).toBe(true);
  });
});

describe.each(ENTRIES)("%s (#3279)", (_name, entry) => {
  it("is disabled, with the reason, for a role with write but no read", async () => {
    const btn = await entry(WRITE_ONLY);
    await act(async () => {
      await served;
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(btn.disabled).toBe(true);
    expect(btn.title).toMatch(REASON);
  });

  it("is disabled while permissions are still loading", async () => {
    const btn = await entry("loading");
    expect(btn.disabled).toBe(true);
  });

  it("is offered with write and read, and to a superadmin", async () => {
    const withRead = await entry(WRITE_READ);
    await waitFor(() => expect(withRead.disabled).toBe(false));
    cleanup();
    const superadmin = await entry("superadmin");
    await waitFor(() => expect(superadmin.disabled).toBe(false));
  });
});
