/**
 * @vitest-environment jsdom
 *
 * Sync > DHCP and Sync > All are offered only to a superadmin (#2699): they
 * POST /dhcp/servers/{id}/sync-leases, a SuperAdmin route. A refusal that
 * still arrives reads as the server's reason, not the transport's
 * "Request failed with status code 403". Real `usePermissions`.
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

const { SubnetDetail, DhcpSyncModal } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-10-22T00:00:00Z";

type G = [string, string, string | null];

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
}

const EDITOR: G[] = [
  ["admin", "ip_space", null],
  ["admin", "ip_block", null],
  ["admin", "subnet", null],
  ["admin", "ip_address", null],
  ["admin", "dns_zone", null],
  ["admin", "dns_record", null],
  ["admin", "dhcp_scope", null],
];

async function openSubnet() {
  answers.ipamApi = { listAddresses: () => Promise.resolve([]) };
  answers.dhcpApi = {
    listScopesBySubnet: () =>
      Promise.resolve([{ id: "sc-1", group_id: "g-1" }]),
    listServers: () => Promise.resolve([]),
  };
  const subnet = {
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
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <SubnetDetail subnet={subnet} onSubnetEdited={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 80));
  });
}

async function item(label: string) {
  fireEvent.click(screen.getByRole("button", { name: /Sync/ }));
  const found = await screen.findAllByText(label);
  return found[0].closest("button") as HTMLButtonElement;
}

describe("subnet Sync > DHCP / All gates (#2699)", () => {
  it("disables both for an IPAM, DNS and DHCP editor, with the reason", async () => {
    signInAs(EDITOR);
    await openSubnet();
    const dhcp = await item("DHCP");
    expect(dhcp.disabled).toBe(true);
    expect(dhcp.title).toBe("Requires superadmin");
    fireEvent.keyDown(document, { key: "Escape" });
    const all = await item("All");
    expect(all.disabled).toBe(true);
    expect(all.title).toBe("Requires superadmin");
  });

  it("enables both for a superadmin", async () => {
    signInAs("superadmin");
    await openSubnet();
    expect((await item("DHCP")).disabled).toBe(false);
    fireEvent.keyDown(document, { key: "Escape" });
    expect((await item("All")).disabled).toBe(false);
  });
});

describe("DHCP Sync dialog refusal (#2699)", () => {
  it("shows the server's reason, not the transport's", async () => {
    answers.dhcpApi = {
      listScopesBySubnet: () =>
        Promise.resolve([{ id: "sc-1", group_id: "g-1" }]),
      listServers: () =>
        Promise.resolve([
          { id: "srv-1", name: "kea1", server_group_id: "g-1" },
        ]),
      syncLeasesNow: () =>
        Promise.reject(
          Object.assign(new Error("Request failed with status code 403"), {
            response: { status: 403, data: { detail: "Superadmin required" } },
          }),
        ),
    };
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <DhcpSyncModal subnetId="sub-1" onClose={() => {}} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByText("Superadmin required")).toBeTruthy();
    expect(screen.queryByText(/status code 403/)).toBeNull();
  });
});
