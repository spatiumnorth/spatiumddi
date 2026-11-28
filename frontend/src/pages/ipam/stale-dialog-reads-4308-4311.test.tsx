/**
 * @vitest-environment jsdom
 *
 * Dialogs that pre-fill or decide from a shared list or Settings read re-read
 * it on open instead of serving the app's 30 s cache (#4308, #4309, #4310,
 * #4311; as #4028 / #4029 / #4030). Each test opens a dialog, closes it,
 * changes what the mocked API answers (another client's edit) and opens it
 * again on the same query cache, seeded as the first open left it.
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
import type { IPAMTemplate } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

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

const { CreateBlockModal, EditBlockModal } = await import("./IPAMPage");
const { ZoneModal, GroupModal } = await import("../dns/DNSPage");
const { DelegationModal } = await import("../dns/DelegationModal");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

// The app's own default (queryClient.ts): a read in the last 30 s is served
// from cache on mount unless the query asks otherwise.
const qc = () =>
  new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 30_000 } },
  });

function mount(client: QueryClient, ui: ReactNode) {
  const r = render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  return () => r.unmount();
}

async function dhcpGroupSelect(): Promise<HTMLSelectElement> {
  return (await screen.findByText("DHCP Server Group"))
    .nextElementSibling as HTMLSelectElement;
}

async function control<T extends HTMLElement = HTMLSelectElement>(
  label: string,
): Promise<T> {
  return (await screen.findByText(label, { selector: "label" }))
    .nextElementSibling as T;
}

describe("New IP Block applies what the template and defaults hold now (#4308)", () => {
  const tpl = (dhcp: string) =>
    ({
      id: "t",
      name: "T",
      description: "",
      applies_to: "block",
      tags: {},
      custom_fields: {},
      dns_group_id: null,
      dns_zone_id: null,
      dns_additional_zone_ids: null,
      dhcp_group_id: dhcp,
      ddns_enabled: false,
      ddns_hostname_policy: "client_or_generated",
      ddns_domain_override: null,
      ddns_ttl: null,
      child_layout: null,
      applied_count: 0,
    }) as unknown as IPAMTemplate;

  it("opened again applies the DHCP group the template holds now", async () => {
    answer("authApi", "myPermissions", () =>
      Promise.resolve({
        is_superadmin: false,
        grants: [
          { action: "read", resource_type: "dhcp_server", resource_id: null },
        ],
      }),
    );
    answer("dhcpApi", "listGroups", () =>
      Promise.resolve([
        { id: "G1", name: "group-one" },
        { id: "G2", name: "group-two" },
      ]),
    );
    answer("ipamApi", "listBlocks", () => Promise.resolve([]));
    answer("customFieldsApi", "list", () => Promise.resolve([]));
    const ui = <CreateBlockModal spaceId="sp" onClose={() => {}} />;
    const client = qc();

    answer("ipamApi", "listTemplates", () => Promise.resolve([tpl("G1")]));
    const close = mount(client, ui);
    const first = await control("Apply template (optional)");
    await waitFor(() => expect(first.disabled).toBe(false));
    fireEvent.change(first, { target: { value: "t" } });
    close();

    answer("ipamApi", "listTemplates", () => Promise.resolve([tpl("G2")]));
    mount(client, ui);
    const second = await control("Apply template (optional)");
    await waitFor(() => expect(second.disabled).toBe(false));
    fireEvent.change(second, { target: { value: "t" } });
    fireEvent.click(screen.getByRole("button", { name: "DHCP" }));
    await waitFor(() => {
      const group = screen.getByText("DHCP Server Group")
        .nextElementSibling as HTMLSelectElement;
      expect(group.value).toBe("G2");
    });
  });

  it("opened again sends the custom field default as it is now", async () => {
    const createBlock = vi.fn(() => Promise.resolve({ id: "b" }));
    answer("ipamApi", "createBlock", createBlock);
    answer("ipamApi", "listBlocks", () => Promise.resolve([]));
    answer("ipamApi", "listTemplates", () => Promise.resolve([]));
    const def = (d: string) => [
      {
        id: "cf",
        name: "owner",
        label: "Owner",
        field_type: "text",
        default_value: d,
        is_required: false,
      },
    ];
    const ui = <CreateBlockModal spaceId="sp" onClose={() => {}} />;
    const client = qc();

    answer("customFieldsApi", "list", () => Promise.resolve(def("one")));
    const close = mount(client, ui);
    await screen.findByDisplayValue("one");
    close();

    answer("customFieldsApi", "list", () => Promise.resolve(def("two")));
    mount(client, ui);
    await screen.findByDisplayValue("two");
    fireEvent.change(await control<HTMLInputElement>("Network (CIDR)"), {
      target: { value: "10.0.0.0/8" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create Block" }));
    await waitFor(() => expect(createBlock).toHaveBeenCalledTimes(1));
    expect(
      (createBlock.mock.calls[0] as unknown as [{ custom_fields: unknown }])[0]
        .custom_fields,
    ).toEqual({ owner: "two" });
  });
});

describe("Add Zone and New Server Group follow Settings as stored now (#4309)", () => {
  it("Add Zone opened again shows the Default TTL, and sends none while untouched", async () => {
    const createZone = vi.fn((_g: unknown, d: unknown) => Promise.resolve(d));
    answer("dnsApi", "createZone", createZone);
    answer("dnsApi", "listGroups", () => Promise.resolve([]));
    answer("dnsApi", "listZones", () => Promise.resolve([]));
    const ui = <ZoneModal groupId="g1" views={[]} onClose={() => {}} />;
    const client = qc();

    answer("settingsApi", "get", () =>
      Promise.resolve({
        dns_default_ttl: 3600,
        dns_default_zone_type: "primary",
      }),
    );
    const close = mount(client, ui);
    await waitFor(async () =>
      expect(
        (await control<HTMLInputElement>("Default TTL (seconds)")).value,
      ).toBe("3600"),
    );
    close();

    answer("settingsApi", "get", () =>
      Promise.resolve({
        dns_default_ttl: 4834,
        dns_default_zone_type: "primary",
      }),
    );
    mount(client, ui);
    await waitFor(async () =>
      expect(
        (await control<HTMLInputElement>("Default TTL (seconds)")).value,
      ).toBe("4834"),
    );
    const name = await control<HTMLInputElement>("Zone Name (FQDN)");
    fireEvent.change(name, { target: { value: "f.example.com" } });
    fireEvent.submit(name.form!);
    await waitFor(() => expect(createZone).toHaveBeenCalledTimes(1));
    const sent = createZone.mock.calls[0][1] as Record<string, unknown>;
    expect(sent.ttl).toBeUndefined();
    expect(sent.zone_type).toBe("primary");
  });

  it("New Server Group opened again starts Recursive from Settings as stored now", async () => {
    answer("dnsApi", "listGroups", () => Promise.resolve([]));
    const ui = <GroupModal onClose={() => {}} />;
    const client = qc();

    answer("settingsApi", "get", () =>
      Promise.resolve({ dns_recursive_by_default: true }),
    );
    const close = mount(client, ui);
    const box = () =>
      screen.getByLabelText("Allow recursion") as HTMLInputElement;
    await waitFor(() => expect(box().checked).toBe(true));
    close();

    answer("settingsApi", "get", () =>
      Promise.resolve({ dns_recursive_by_default: false }),
    );
    mount(client, ui);
    await waitFor(() => expect(box().checked).toBe(false));
  });
});

describe("Delegate lists what Apply creates (#4310)", () => {
  const preview = (names: string[]) => ({
    has_parent: true,
    parent_zone_id: "p",
    parent_zone_name: "example.test.",
    child_zone_id: "c",
    child_zone_name: "sub.example.test.",
    child_label: "sub",
    ns_records_to_create: names.map((v) => ({
      name: "sub",
      record_type: "NS",
      value: v,
      ttl: null,
    })),
    glue_records_to_create: [],
    existing_ns_records: [],
    existing_glue_records: [],
    warnings: [],
    child_apex_ns_count: names.length,
  });
  const ui = (
    <DelegationModal
      groupId="g"
      zoneId="c"
      zoneName="sub.example.test."
      onClose={() => {}}
    />
  );

  it("opened again lists the NS records the child holds now", async () => {
    const client = qc();
    answer("dnsApi", "getDelegationPreview", () =>
      Promise.resolve(preview(["ns1.example.net."])),
    );
    const close = mount(client, ui);
    await screen.findByText("ns1.example.net.");
    close();

    answer("dnsApi", "getDelegationPreview", () =>
      Promise.resolve(preview(["ns1.example.net.", "ns2.example.net."])),
    );
    mount(client, ui);
    await screen.findByText("ns2.example.net.");
  });

  it("Apply does not write a list the dialog did not show", async () => {
    const apply = vi.fn(() => Promise.resolve([]));
    answer("dnsApi", "applyDelegation", apply);
    const client = qc();
    answer("dnsApi", "getDelegationPreview", () =>
      Promise.resolve(preview(["ns1.example.net."])),
    );
    mount(client, ui);
    await screen.findByText("ns1.example.net.");
    // Another client adds an apex NS while the dialog is open.
    answer("dnsApi", "getDelegationPreview", () =>
      Promise.resolve(preview(["ns1.example.net.", "ns2.example.net."])),
    );
    fireEvent.click(screen.getByRole("button", { name: "Apply delegation" }));
    await screen.findByText(/changed since this list was shown/);
    await screen.findByText("ns2.example.net.");
    expect(apply).not.toHaveBeenCalled();
  });
});

describe("Edit Block names the DHCP group another client just made (#4311)", () => {
  it("opened again shows the stored group, not None", async () => {
    const group = (ids: string[]) =>
      ids.map((id) => ({ id, name: `group-${id}` }));
    const block = (g: string) =>
      ({
        id: "b-1",
        space_id: "sp-1",
        parent_block_id: null,
        network: "10.98.0.0/16",
        name: "top",
        dns_inherit_settings: true,
        dhcp_inherit_settings: false,
        dhcp_server_group_id: g,
        dns_group_ids: [],
        dns_zone_id: null,
        dns_additional_zone_ids: [],
        utilization_percent: 0,
        allocated_ips: 0,
        total_ips: 65536,
      }) as never;
    answer("authApi", "myPermissions", () =>
      Promise.resolve({
        is_superadmin: true,
        grants: [],
      }),
    );
    answer("ipamApi", "getEffectiveSpaceDhcp", () => Promise.resolve(null));
    const client = qc();

    answer("dhcpApi", "listGroups", () => Promise.resolve(group(["G1"])));
    answer("ipamApi", "getBlock", () => Promise.resolve(block("G1")));
    const close = mount(
      client,
      <EditBlockModal block={block("G1")} onClose={() => {}} />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "DHCP" }));
    await waitFor(async () =>
      expect((await dhcpGroupSelect()).value).toBe("G1"),
    );
    close();

    answer("dhcpApi", "listGroups", () => Promise.resolve(group(["G1", "G2"])));
    answer("ipamApi", "getBlock", () => Promise.resolve(block("G2")));
    mount(client, <EditBlockModal block={block("G1")} onClose={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "DHCP" }));
    await waitFor(async () =>
      expect((await dhcpGroupSelect()).value).toBe("G2"),
    );
  });
});
