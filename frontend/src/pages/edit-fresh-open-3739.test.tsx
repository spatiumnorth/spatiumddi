/**
 * @vitest-environment jsdom
 *
 * The DNS group Options tab, Edit DHCP Server, Edit Blocked Domain, Edit
 * Exception and the IPAM Imported chip read the object fresh and send only
 * what the operator changed (#3739), the #3365 / #3379 pattern. Each is handed
 * a stale copy while the API holds the newer one.
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
  DHCPServer,
  DNSBlockList,
  DNSBlockListEntry,
  DNSBlockListException,
  DNSServerOptions,
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

const { OptionsTab, BlocklistDetail } = await import("@/pages/dns/DNSPage");
const { CreateServerModal } = await import("@/pages/dhcp/CreateServerModal");
const { ImportedChip } = await import("@/pages/ipam/IPAMPage");

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
  return qc;
}

const opts = (over: Partial<DNSServerOptions> = {}) =>
  ({
    id: "o-1",
    group_id: "g-1",
    forwarders: [],
    forward_policy: "first",
    recursion_enabled: true,
    allow_recursion: ["localhost"],
    dnssec_validation: "auto",
    notify_enabled: "yes",
    allow_query: ["any"],
    allow_transfer: ["none"],
    query_log_enabled: false,
    response_log_enabled: false,
    query_log_channel: "file",
    query_log_file: "/var/log/named/queries.log",
    query_log_severity: "info",
    rrl_enabled: false,
    rrl_responses_per_second: 15,
    rrl_window: 15,
    rrl_slip: 2,
    rrl_qps_scale: null,
    rrl_exempt_clients: [],
    rrl_log_only: false,
    minimal_responses: false,
    tcp_clients: null,
    clients_per_query: null,
    max_clients_per_query: null,
    dnsdist_enabled: false,
    dnsdist_max_qps_per_client: null,
    dnsdist_action: "truncate",
    dnsdist_dynblock_qps: null,
    dnsdist_dynblock_seconds: 60,
    dot_enabled: false,
    dot_port: 853,
    doh_enabled: false,
    doh_port: 443,
    doh_path: "/dns-query",
    doq_enabled: false,
    doq_port: 853,
    tls_certificate_id: null,
    forward_transport: "do53",
    forward_tls_hostname: null,
    forward_tls_verify: true,
    trust_anchors: [],
    ...over,
  }) as unknown as DNSServerOptions;

describe("DNS group Options tab (#3739)", () => {
  it("fills from a fresh read, not the cache, and sends only the changed option", async () => {
    const stale = opts();
    const fresh = opts({
      recursion_enabled: false,
      forwarders: ["192.0.2.53"],
      tcp_clients: 150,
    });
    const updateOptions = vi.fn(() => Promise.resolve(fresh));
    answers.dnsApi = {
      getOptions: () => Promise.resolve(fresh),
      updateOptions,
      listServers: () => Promise.resolve([]),
    };
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    client.setQueryData(["dns-options", "g-1"], stale);
    open(<OptionsTab groupId="g-1" />, client);
    await waitFor(() =>
      expect(screen.getByDisplayValue("192.0.2.53")).toBeTruthy(),
    );
    const minimal = screen
      .getByText(/minimal-responses/)
      .closest("label")!
      .querySelector("input")!;
    fireEvent.click(minimal);
    fireEvent.click(screen.getByRole("button", { name: /Save Changes/ }));
    await waitFor(() => expect(updateOptions).toHaveBeenCalled());
    expect(updateOptions).toHaveBeenCalledWith("g-1", {
      minimal_responses: true,
    });
  });

  it("a header Refresh re-fills an untouched form from the new read", async () => {
    let current = opts();
    const updateOptions = vi.fn(() => Promise.resolve(current));
    answers.dnsApi = {
      getOptions: () => Promise.resolve(current),
      updateOptions,
      listServers: () => Promise.resolve([]),
    };
    const client = open(<OptionsTab groupId="g-1" />);
    await screen.findByText(/minimal-responses/);
    await waitFor(() => expect(screen.queryByText("Loading…")).toBeNull());
    current = opts({ recursion_enabled: false, forwarders: ["192.0.2.53"] });
    await client.invalidateQueries({ queryKey: ["dns-options", "g-1"] });
    await waitFor(() =>
      expect(screen.getByDisplayValue("192.0.2.53")).toBeTruthy(),
    );
    const minimal = screen
      .getByText(/minimal-responses/)
      .closest("label")!
      .querySelector("input")!;
    fireEvent.click(minimal);
    fireEvent.click(screen.getByRole("button", { name: /Save Changes/ }));
    await waitFor(() => expect(updateOptions).toHaveBeenCalled());
    expect(updateOptions).toHaveBeenCalledWith("g-1", {
      minimal_responses: true,
    });
  });
});

describe("Edit DHCP Server (#3739)", () => {
  const stale = {
    id: "s-1",
    server_group_id: "g-1",
    name: "kea1",
    description: "d",
    driver: "kea",
    host: "10.133.128.9",
    port: 67,
    has_credentials: false,
  } as unknown as DHCPServer;
  const fresh = { ...stale, host: "10.133.128.10" } as DHCPServer;

  it("shows the stored host and sends only the changed description", async () => {
    const updateServer = vi.fn(() => Promise.resolve(fresh));
    answers.dhcpApi = {
      getServer: () => Promise.resolve(fresh),
      listGroups: () => Promise.resolve([]),
      updateServer,
    };
    open(<CreateServerModal server={stale} onClose={() => {}} />);
    const desc = await screen.findByDisplayValue("d");
    expect(screen.getByDisplayValue("10.133.128.10")).toBeTruthy();
    fireEvent.change(desc, { target: { value: "new" } });
    fireEvent.submit(desc.closest("form")!);
    await waitFor(() => expect(updateServer).toHaveBeenCalled());
    expect(updateServer).toHaveBeenCalledWith("s-1", { description: "new" });
  });

  it("an untouched Save sends nothing and closes", async () => {
    const updateServer = vi.fn(() => Promise.resolve(fresh));
    const onClose = vi.fn();
    answers.dhcpApi = {
      getServer: () => Promise.resolve(fresh),
      listGroups: () => Promise.resolve([]),
      updateServer,
    };
    open(<CreateServerModal server={stale} onClose={onClose} />);
    const desc = await screen.findByDisplayValue("d");
    fireEvent.submit(desc.closest("form")!);
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateServer).not.toHaveBeenCalled();
  });

  it("a failed read shows the error, not a form", async () => {
    answers.dhcpApi = {
      getServer: () => Promise.reject(new Error("boom")),
      listGroups: () => Promise.resolve([]),
    };
    open(<CreateServerModal server={stale} onClose={() => {}} />);
    await screen.findByText(/boom/);
    expect(screen.queryByDisplayValue("10.133.128.9")).toBeNull();
  });
});

describe("Blocklist entry + exception edits (#3739)", () => {
  const list = { id: "l-1", name: "mine" } as unknown as DNSBlockList;
  const entry = (over: Partial<DNSBlockListEntry> = {}) =>
    ({
      id: "e-1",
      list_id: "l-1",
      domain: "bad.example",
      entry_type: "block",
      target: null,
      source: "manual",
      is_wildcard: true,
      reason: "r",
      added_at: "",
      ...over,
    }) as DNSBlockListEntry;
  const exc = (over: Partial<DNSBlockListException> = {}) =>
    ({ id: "x-1", domain: "ok.example", reason: "rx", ...over }) as never;

  it("Edit Blocked Domain shows the stored wildcard and sends only the reason", async () => {
    const updateEntry = vi.fn(() => Promise.resolve(entry()));
    let stored = entry();
    answers.dnsBlocklistApi = {
      listEntries: () =>
        Promise.resolve({ items: [stored], total: 1, limit: 50, offset: 0 }),
      listExceptions: () => Promise.resolve([]),
      updateEntry,
    };
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    open(<BlocklistDetail list={list} onBack={() => {}} />, client);
    const pencil = await screen.findByLabelText("Edit domain");
    // Another client turns the wildcard off after the table loaded.
    stored = entry({ is_wildcard: false });
    fireEvent.click(pencil);
    const reason = await screen.findByDisplayValue("r");
    const box = screen
      .getByText(/Block subdomains too/)
      .closest("label")!
      .querySelector("input")!;
    expect(box.checked).toBe(false);
    fireEvent.change(reason, { target: { value: "xp r2" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateEntry).toHaveBeenCalled());
    expect(updateEntry).toHaveBeenCalledWith("l-1", "e-1", {
      reason: "xp r2",
    });
  });

  it("Edit Exception sends only the changed field from the fresh row", async () => {
    const updateException = vi.fn(() => Promise.resolve(exc()));
    let stored = exc();
    answers.dnsBlocklistApi = {
      listEntries: () =>
        Promise.resolve({ items: [], total: 0, limit: 50, offset: 0 }),
      listExceptions: () => Promise.resolve([stored]),
      updateException,
    };
    open(<BlocklistDetail list={list} onBack={() => {}} />);
    const pencil = await screen.findByLabelText("Edit exception");
    stored = exc({ domain: "moved.example" });
    fireEvent.click(pencil);
    const reason = await screen.findByDisplayValue("rx");
    expect(screen.getByDisplayValue("moved.example")).toBeTruthy();
    fireEvent.change(reason, { target: { value: "new" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateException).toHaveBeenCalled());
    expect(updateException).toHaveBeenCalledWith("l-1", "x-1", {
      reason: "new",
    });
  });
});

describe("IPAM Imported chip dismiss (#3739)", () => {
  it("sends the custom fields read now, not the detail view's copy", async () => {
    const updateBlock = vi.fn(() => Promise.resolve({ id: "b-1" }));
    answers.ipamApi = {
      // Another client set `owner` after the detail view loaded.
      getBlock: () =>
        Promise.resolve({
          id: "b-1",
          custom_fields: { import_source: "netbox", site: "a", owner: "bob" },
        }),
      updateBlock,
    };
    open(
      <ImportedChip
        fields={{ import_source: "netbox" }}
        kind="block"
        id="b-1"
        onUpdated={() => {}}
      />,
    );
    fireEvent.click(screen.getByLabelText(/Remove import metadata/));
    fireEvent.click(await screen.findByRole("button", { name: "Remove" }));
    await waitFor(() => expect(updateBlock).toHaveBeenCalled());
    expect(updateBlock).toHaveBeenCalledWith("b-1", {
      custom_fields: { site: "a", owner: "bob" },
    });
  });
});
