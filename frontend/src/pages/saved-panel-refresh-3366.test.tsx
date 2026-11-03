/**
 * @vitest-environment jsdom
 *
 * A panel shows what a Save stored, not what the object looked like when it
 * was clicked (#3366, #3369): the DHCP group panel and the IPAM block panel
 * follow the refreshed list, and the DHCP server / group Edit dialogs write
 * the Save's answer into the cached copies the page reads.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

const ok = (v: unknown) => () => Promise.resolve(v);

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

const { DHCPPage } = await import("@/pages/dhcp/DHCPPage");
const { BlockDetailView, IPAMPage } = await import("@/pages/ipam/IPAMPage");
const { CreateServerModal } = await import("@/pages/dhcp/CreateServerModal");
const { CreateServerGroupModal } =
  await import("@/pages/dhcp/CreateServerGroupModal");

function mount(el: React.ReactElement, client?: QueryClient, url = "/") {
  const c =
    client ??
    new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrap = (e: React.ReactElement) => (
    <QueryClientProvider client={c}>
      <MemoryRouter initialEntries={[url]}>{e}</MemoryRouter>
    </QueryClientProvider>
  );
  const r = render(wrap(el));
  return { c, rerender: (e: React.ReactElement) => r.rerender(wrap(e)) };
}

afterEach(() => {
  cleanup();
  for (const k of Object.keys(answers)) delete answers[k];
  try {
    sessionStorage.clear();
  } catch {
    // jsdom without storage: nothing to clear.
  }
});

const grp = (description: string) => ({
  id: "g1",
  name: "grp1",
  description,
  mode: "standalone",
  servers: [],
});
const srv = (description: string) => ({
  id: "s1",
  name: "kea1",
  description,
  driver: "kea",
  host: "10.0.0.1",
  port: 67,
  server_group_id: "g1",
  ha_peer_url: "",
});

describe("#3369 panels follow the refreshed list", () => {
  it("the DHCP group panel shows the description a Save stored", async () => {
    answers.dhcpApi = {
      listGroups: ok([grp("xp g1")]),
      listServers: ok([]),
      getGroup: ok(grp("xp g1")),
    };
    const { c } = mount(<DHCPPage />);
    fireEvent.click(await screen.findByText("grp1"));
    await screen.findByText("xp g1");
    act(() => {
      c.setQueryData(["dhcp-groups"], [grp("xp g2")]);
    });
    await screen.findByText("xp g2");
    expect(screen.queryByText("xp g1")).toBeNull();
  });

  it("the block panel shows the description a Save stored", async () => {
    answers.ipamApi = { blockFreeSpace: ok([]) };
    const b = (description: string) =>
      ({
        id: "b1",
        space_id: "sp1",
        network: "10.237.0.0/16",
        name: "blk",
        description,
        parent_block_id: null,
      }) as never;
    const props = {
      spaceName: "space1",
      ancestors: [],
      allSubnets: [],
      onSelectSpace: () => {},
      onSelectBlock: () => {},
      onSelectSubnet: () => {},
    };
    const { rerender } = mount(
      <BlockDetailView
        block={b("xp p1")}
        allBlocks={[b("xp p1")]}
        {...props}
      />,
    );
    await screen.findByText(/xp p1/);
    // The page's selection is still the click-time object; only the list moved.
    rerender(
      <BlockDetailView
        block={b("xp p1")}
        allBlocks={[b("xp p2")]}
        {...props}
      />,
    );
    await screen.findByText(/xp p2/);
    expect(screen.queryByText(/xp p1/)).toBeNull();
  });

  it("the server page's group follows a move made with Edit DHCP Server", async () => {
    const g2 = { ...grp("other"), id: "g2", name: "grp2" };
    answers.dhcpApi = {
      listGroups: ok([grp("xp g1"), g2]),
      listServers: ok([srv("xp d1")]),
      getServer: ok(srv("xp d1")),
    };
    const { c } = mount(<DHCPPage />, undefined, "/dhcp?server=s1");
    await screen.findByText("Group: grp1");
    act(() => {
      c.setQueryData(["dhcp-server", "s1"], {
        ...srv("xp d1"),
        server_group_id: "g2",
      });
    });
    await screen.findByText("Group: grp2");
  });

  it("the server inspector follows the refreshed list after Pause", async () => {
    answers.dhcpApi = {
      listGroups: ok([grp("xp g1")]),
      listServers: ok([srv("xp d1")]),
    };
    const { c } = mount(<DHCPPage />, undefined, "/dhcp?group=g1");
    fireEvent.click(
      await screen.findByRole("button", { name: "View details of kea1" }),
    );
    const dialog = await screen.findByRole("dialog");
    await within(dialog).findByRole("button", { name: /Pause/ });
    act(() => {
      c.setQueryData(
        ["dhcp-servers", "all"],
        [{ ...srv("xp d1"), maintenance_mode: true }],
      );
    });
    await within(dialog).findByRole("button", { name: /Resume/ });
  });

  it("the block breadcrumb follows a block moved under another", async () => {
    const parent = {
      id: "b0",
      space_id: "sp1",
      network: "10.0.0.0/8",
      name: "parentblk",
      description: "",
      parent_block_id: null,
      custom_fields: {},
      tags: {},
    };
    const child = {
      ...parent,
      id: "b1",
      network: "10.237.0.0/16",
      name: "blk",
    };
    answers.ipamApi = {
      listSpaces: ok([{ id: "sp1", name: "space1", custom_fields: {} }]),
      listBlocks: ok([parent, child]),
      listSubnets: ok([]),
      getBlock: ok(child),
      blockFreeSpace: ok([]),
    };
    const { c } = mount(<IPAMPage />, undefined, "/ipam?block=b1");
    await screen.findAllByText(/10\.237\.0\.0\/16/);
    expect(screen.queryByText("10.0.0.0/8 (parentblk)")).toBeNull();
    act(() => {
      c.setQueryData(
        ["blocks", "sp1"],
        [parent, { ...child, parent_block_id: "b0" }],
      );
    });
    await screen.findByText("10.0.0.0/8 (parentblk)");
  });
});

describe("#3366 / #3369 a Save writes its answer into the cached copies", () => {
  it("Edit DHCP Server updates the page's own server copy at once", async () => {
    answers.dhcpApi = {
      listGroups: ok([]),
      updateServer: ok({ ...srv("xp d2") }),
    };
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    client.setQueryData(["dhcp-server", "s1"], srv("xp d1"));
    client.setQueryData(["dhcp-servers", "all"], [srv("xp d1")]);
    client.setQueryData(["dhcp-servers", "g1"], [srv("xp d1")]);
    mount(
      <CreateServerModal server={srv("xp d1") as never} onClose={() => {}} />,
      client,
    );
    fireEvent.submit(screen.getByLabelText(/^Name/).closest("form")!);
    await waitFor(() =>
      expect(
        (client.getQueryData(["dhcp-server", "s1"]) as { description: string })
          .description,
      ).toBe("xp d2"),
    );
    expect(
      (
        client.getQueryData(["dhcp-servers", "all"]) as {
          description: string;
        }[]
      )[0].description,
    ).toBe("xp d2");
    expect(
      (
        client.getQueryData(["dhcp-servers", "g1"]) as {
          description: string;
        }[]
      )[0].description,
    ).toBe("xp d2");
  });

  it("Edit Server Group updates the cached group list at once", async () => {
    answers.dhcpApi = {
      getGroup: ok(grp("xp g1")),
      updateGroup: ok(grp("xp g2")),
    };
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    client.setQueryData(["dhcp-groups"], [grp("xp g1")]);
    mount(
      <CreateServerGroupModal
        group={grp("xp g1") as never}
        onClose={() => {}}
      />,
      client,
    );
    const field = (await screen.findByDisplayValue(
      "xp g1",
    )) as HTMLInputElement;
    fireEvent.change(field, { target: { value: "xp g2" } });
    fireEvent.submit(field.closest("form")!);
    await waitFor(() =>
      expect(
        (client.getQueryData(["dhcp-groups"]) as { description: string }[])[0]
          .description,
      ).toBe("xp g2"),
    );
  });
});
