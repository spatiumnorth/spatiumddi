/**
 * @vitest-environment jsdom
 *
 * #3361: DNS views show the padlock, disable Delete with the reason and offer
 * Lock / Unlock behind the grant; the zone list's "Locked" filter narrows it.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { DNSServerGroup } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
let granted = new Set<string>();

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
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: (action: string, resource: string) =>
        granted.has(`${action}:${resource}`),
      isSuperadmin: false,
    }),
  };
});

const { ViewsTab, ZonesTab } = await import("./DNSPage");
afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const GROUP = { id: "g1", name: "grp" } as unknown as DNSServerGroup;

function mount(ui: React.ReactElement) {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("DNS view locks (#3361)", () => {
  const views = [
    {
      id: "v1",
      group_id: "g1",
      name: "internal",
      description: "",
      order: 1,
      recursion: true,
      match_clients: ["10.0.0.0/8"],
      lock_level: "delete",
      locked_by: "bob",
      lock_reason: "audit hold",
    },
    {
      id: "v2",
      group_id: "g1",
      name: "guest",
      description: "",
      order: 2,
      recursion: true,
      match_clients: ["any"],
      lock_level: null,
    },
  ];

  it("a locked view: badge, Delete disabled with the reason, Unlock offered", async () => {
    granted = new Set([
      "write:dns_group",
      "delete:dns_group",
      "lock:dns_group",
    ]);
    answers.dnsApi = {
      listViews: () => Promise.resolve(views),
      listServers: () => Promise.resolve([]),
    };
    answers.dnsBlocklistApi = { list: () => Promise.resolve([]) };
    mount(<ViewsTab group={GROUP} />);
    await screen.findByText("internal");
    expect(screen.getAllByTestId("lock-badge")).toHaveLength(1);
    const dels = screen.getAllByRole("button", { name: "Delete view" });
    expect((dels[0] as HTMLButtonElement).disabled).toBe(true);
    expect((dels[0] as HTMLButtonElement).title).toContain("audit hold");
    expect((dels[1] as HTMLButtonElement).disabled).toBe(false);
    expect(screen.getByRole("button", { name: "Unlock view" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Lock view" })).toBeTruthy();
  });

  it("no Lock / Unlock without the grant", async () => {
    granted = new Set(["write:dns_group", "delete:dns_group"]);
    answers.dnsApi = {
      listViews: () => Promise.resolve(views),
      listServers: () => Promise.resolve([]),
    };
    answers.dnsBlocklistApi = { list: () => Promise.resolve([]) };
    mount(<ViewsTab group={GROUP} />);
    await screen.findByText("internal");
    expect(
      screen.queryByRole("button", { name: /^(Un)?[Ll]ock view/ }),
    ).toBeNull();
  });
});

describe("DNS zone list lock filter (#3361)", () => {
  it("narrows the zones to locked or unlocked", async () => {
    granted = new Set(["read:dns_zone"]);
    const zone = (id: string, name: string, extra: object) => ({
      id,
      group_id: "g1",
      name,
      zone_type: "primary",
      kind: "forward",
      ttl: 3600,
      dnssec_enabled: false,
      tags: {},
      ...extra,
    });
    answers.dnsApi = {
      listZones: () =>
        Promise.resolve([
          zone("z1", "locked.example.", {
            lock_level: "edit",
            locked_by: "alice",
            lock_reason: "freeze",
          }),
          zone("z2", "open.example.", { lock_level: null }),
        ]),
      listViews: () => Promise.resolve([]),
    };
    mount(<ZonesTab group={GROUP} onSelectZone={() => {}} />);
    await screen.findByText("locked.example");
    // Zone filters sit behind the table's filter toggle.
    fireEvent.click(screen.getByTitle("Toggle filters"));
    const select = screen.getByLabelText("Filter by lock");
    fireEvent.change(select, { target: { value: "locked" } });
    expect(screen.queryByText("open.example")).toBeNull();
    expect(screen.getByText("locked.example")).toBeTruthy();
    fireEvent.change(select, { target: { value: "unlocked" } });
    expect(screen.queryByText("locked.example")).toBeNull();
    expect(screen.getByText("open.example")).toBeTruthy();
  });
});
