/**
 * @vitest-environment jsdom
 *
 * A DNS / DHCP / IPAM list the server refused is not an empty estate (#3337,
 * #2437's class). A role that reads one type and not the next is refused the
 * next list with a 403; each view below used to answer that with its
 * "No server groups yet." / "No zones" / "No blocks yet." sentence. Each is held
 * to saying the read was refused, and keeps the empty sentence for a list that
 * answered and was empty.
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

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

function refused() {
  return Object.assign(new Error("Request failed with status code 403"), {
    isAxiosError: true,
    response: { status: 403, data: { detail: "Permission denied" } },
  });
}
const ok = (v: unknown) => () => Promise.resolve(v);
const no = () => Promise.reject(refused());

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
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { DHCPPage, ServerScopesTab, ServerPoolsOrStaticsTab } =
  await import("@/pages/dhcp/DHCPPage");
const { DNSPage, ZoneDetailView } = await import("@/pages/dns/DNSPage");
const { IPAMPage, BlockDetailView } = await import("@/pages/ipam/IPAMPage");
const { FreeSpaceBand } = await import("@/components/ipam/FreeSpaceBand");
const { FreeSpaceTreemap } = await import("@/components/ipam/FreeSpaceTreemap");

function open(page: React.ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{page}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  for (const k of Object.keys(answers)) delete answers[k];
  try {
    sessionStorage.clear();
  } catch {
    // jsdom without storage: nothing was kept to clear.
  }
});

const group = { id: "g1", name: "grp1", description: "" };
const space = { id: "sp1", name: "space1", description: "" };
const block = {
  id: "b1",
  space_id: "sp1",
  network: "10.237.0.0/16",
  name: "blk",
  parent_block_id: null,
} as never;

describe("DHCP", () => {
  it("the server group list says it was refused", async () => {
    answers.dhcpApi = { listGroups: no, listServers: ok([]) };
    open(<DHCPPage />);
    await screen.findByText(/don't have permission to see DHCP server groups/);
    expect(screen.queryByText("No server groups yet.")).toBeNull();
  });

  it("an empty readable group list still says so", async () => {
    answers.dhcpApi = { listGroups: ok([]), listServers: ok([]) };
    open(<DHCPPage />);
    await screen.findByText("No server groups yet.");
  });

  it("a group's Scopes tab says its scopes were refused", async () => {
    answers.dhcpApi = {
      listGroups: ok([group]),
      listScopesByGroup: no,
      listServers: ok([]),
    };
    answers.ipamApi = { listSubnets: ok([]) };
    open(<ServerScopesTab groupId="g1" />);
    await waitFor(() =>
      expect(
        screen.getAllByText(/don't have permission to see this group's scopes/)
          .length,
      ).toBeGreaterThan(0),
    );
    expect(screen.queryByText("No scopes on this server.")).toBeNull();
    expect(screen.queryByText(/0 scopes on this group/)).toBeNull();
  });

  it("an empty readable scope list still says so", async () => {
    answers.dhcpApi = {
      listGroups: ok([group]),
      listScopesByGroup: ok([]),
      listServers: ok([]),
    };
    answers.ipamApi = { listSubnets: ok([]) };
    open(<ServerScopesTab groupId="g1" />);
    await screen.findByText("No scopes on this server.");
  });
});

describe("DNS", () => {
  it("the server group list says it was refused", async () => {
    answers.dnsApi = { listGroups: no, listServers: ok([]) };
    open(<DNSPage />);
    await screen.findByText(/don't have permission to see DNS server groups/);
    expect(screen.queryByText("No server groups yet.")).toBeNull();
  });

  it("a group's zone tree says its zones were refused", async () => {
    answers.dnsApi = {
      listGroups: ok([group]),
      listServers: ok([]),
      listZones: no,
      listViews: ok([]),
    };
    open(<DNSPage />);
    fireEvent.click(await screen.findByText("grp1"));
    await screen.findByText(/don't have permission to see this group's zones/);
    expect(screen.queryByText("No zones")).toBeNull();
  });

  it("an empty readable zone tree still says so", async () => {
    answers.dnsApi = {
      listGroups: ok([group]),
      listServers: ok([]),
      listZones: ok([]),
      listViews: ok([]),
    };
    open(<DNSPage />);
    fireEvent.click(await screen.findByText("grp1"));
    await screen.findByText("No zones");
  });
});

describe("IPAM", () => {
  it("a space's tree node says its blocks were refused", async () => {
    answers.ipamApi = {
      listSpaces: ok([space]),
      listBlocks: no,
      listSubnets: no,
    };
    open(<IPAMPage />);
    fireEvent.click(await screen.findByText("space1"));
    await waitFor(() =>
      expect(
        screen.getAllByText(
          /don't have permission to see this space's blocks and subnets/,
        ).length,
      ).toBeGreaterThan(0),
    );
    expect(screen.queryByText("No blocks yet.")).toBeNull();
    expect(screen.queryByText(/No blocks or subnets in this space/)).toBeNull();
  });

  it("an empty readable space still says so", async () => {
    answers.ipamApi = {
      listSpaces: ok([space]),
      listBlocks: ok([]),
      listSubnets: ok([]),
    };
    open(<IPAMPage />);
    fireEvent.click(await screen.findByText("space1"));
    await screen.findByText("No blocks yet.");
  });

  it("a block view says its subnets were refused", async () => {
    answers.ipamApi = { blockFreeSpace: no };
    open(
      <BlockDetailView
        block={block}
        spaceName="space1"
        ancestors={[]}
        allBlocks={[]}
        allSubnets={[]}
        readError={refused()}
        onSelectSpace={() => {}}
        onSelectBlock={() => {}}
        onSelectSubnet={() => {}}
      />,
    );
    await screen.findByText(
      /don't have permission to see this block's child blocks and subnets/,
    );
    expect(
      screen.queryByText("This block has no child blocks or subnets yet."),
    ).toBeNull();
  });

  it("a block with no refusal still says it has no children", async () => {
    answers.ipamApi = { blockFreeSpace: ok([]) };
    open(
      <BlockDetailView
        block={block}
        spaceName="space1"
        ancestors={[]}
        allBlocks={[]}
        allSubnets={[]}
        onSelectSpace={() => {}}
        onSelectBlock={() => {}}
        onSelectSubnet={() => {}}
      />,
    );
    await screen.findByText("This block has no child blocks or subnets yet.");
  });

  it("the allocation map says it was refused, band and treemap", async () => {
    answers.ipamApi = { blockFreeSpace: no };
    open(
      <>
        <FreeSpaceBand
          block={block}
          directSubnets={[]}
          childBlocks={[]}
          onSelectFree={() => {}}
        />
        <FreeSpaceTreemap block={block} directSubnets={[]} childBlocks={[]} />
      </>,
    );
    await waitFor(() =>
      expect(
        screen.getAllByText(
          /don't have permission to see this block's allocation map/,
        ),
      ).toHaveLength(2),
    );
    expect(screen.queryByText("No allocation data")).toBeNull();
  });
});

// The related reads the issue's nine views lead to: the next type down from
// a list the role can read (#3337 validation).
function failed() {
  return Object.assign(new Error("Request failed with status code 500"), {
    isAxiosError: true,
    response: { status: 500, data: { detail: "database unavailable" } },
  });
}

describe("the next read down", () => {
  it("a failure that is not a refusal is not called one", async () => {
    answers.dhcpApi = {
      listGroups: () => Promise.reject(failed()),
      listServers: ok([]),
    };
    open(<DHCPPage />);
    await screen.findByText(/Couldn't load DHCP server groups/);
    expect(screen.queryByText(/permission/)).toBeNull();
    expect(screen.queryByText("No server groups yet.")).toBeNull();
  });

  it("a DNS group's Zones and Records tabs say they were refused", async () => {
    answers.dnsApi = {
      listGroups: ok([group]),
      listServers: ok([]),
      listZones: no,
      listViews: ok([]),
      listGroupRecords: no,
    };
    open(<DNSPage />);
    fireEvent.click(await screen.findByText("grp1"));
    fireEvent.click(await screen.findByRole("button", { name: /^Zones/ }));
    await waitFor(() =>
      expect(
        screen.getAllByText(/don't have permission to see this group's zones/)
          .length,
      ).toBe(2),
    );
    expect(screen.queryByText(/No zones yet/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /^Records/ }));
    await screen.findByText(
      /don't have permission to see this group's records/,
    );
    expect(screen.queryByText("No records in this group yet.")).toBeNull();
  });

  it("a zone's record list says it was refused", async () => {
    answers.dnsApi = { listRecords: no };
    open(
      <ZoneDetailView
        group={group as never}
        zone={
          {
            id: "z1",
            group_id: "g1",
            name: "example.com.",
            zone_type: "primary",
            kind: "forward",
          } as never
        }
        onDeleted={() => {}}
      />,
    );
    await screen.findByText(/don't have permission to see this zone's records/);
    expect(screen.queryByText(/No records yet/)).toBeNull();
  });

  it("a DHCP group's Pools and Statics tabs say they were refused", async () => {
    const scope = { id: "sc1", name: "s", subnet_id: "sn1" };
    answers.dhcpApi = {
      listScopesByGroup: ok([scope]),
      listPools: no,
      listStatics: no,
      scopePoolOccupancy: ok([]),
    };
    answers.ipamApi = { listSubnets: ok([]) };
    open(<ServerPoolsOrStaticsTab groupId="g1" kind="pools" />);
    await screen.findByText(/don't have permission to see this group's pools/);
    expect(screen.queryByText("No pools yet.")).toBeNull();
    cleanup();
    open(<ServerPoolsOrStaticsTab groupId="g1" kind="statics" />);
    await screen.findByText(
      /don't have permission to see this group's static assignments/,
    );
    expect(screen.queryByText("No static assignments yet.")).toBeNull();
  });

  it("an empty readable pool list still says so", async () => {
    answers.dhcpApi = {
      listScopesByGroup: ok([{ id: "sc1", name: "s", subnet_id: "sn1" }]),
      listPools: ok([]),
      scopePoolOccupancy: ok([]),
    };
    answers.ipamApi = { listSubnets: ok([]) };
    open(<ServerPoolsOrStaticsTab groupId="g1" kind="pools" />);
    await screen.findByText("No pools yet.");
  });

  it("a block view showing child blocks says its subnets were refused", async () => {
    answers.ipamApi = { blockFreeSpace: ok([]) };
    const child = {
      id: "b2",
      space_id: "sp1",
      network: "10.237.1.0/24",
      name: "child",
      parent_block_id: "b1",
      utilization_percent: 0,
    };
    open(
      <BlockDetailView
        block={block}
        spaceName="space1"
        ancestors={[]}
        allBlocks={[child] as never}
        allSubnets={[]}
        readError={refused()}
        onSelectSpace={() => {}}
        onSelectBlock={() => {}}
        onSelectSubnet={() => {}}
      />,
    );
    await screen.findByText(
      /don't have permission to see all of this block's contents/,
    );
  });

  it("IPAMPage hands the block view its refused subnet read", async () => {
    answers.ipamApi = {
      listSpaces: ok([space]),
      listBlocks: ok([{ ...(block as object), utilization_percent: 0 }]),
      listSubnets: no,
      blockFreeSpace: ok([]),
    };
    open(<IPAMPage />);
    fireEvent.click(await screen.findByText("space1"));
    await screen.findByText(
      /don't have permission to see this space's subnets/,
    );
    fireEvent.click((await screen.findAllByText(/^10\.237\.0\.0/))[0]!);
    await screen.findByText(
      /don't have permission to see this block's child blocks and subnets/,
    );
    expect(
      screen.queryByText("This block has no child blocks or subnets yet."),
    ).toBeNull();
  });
});
