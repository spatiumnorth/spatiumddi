/**
 * @vitest-environment jsdom
 *
 * Dialogs that pick from a cached list re-read it on open, and hold their
 * pick until it answers (#4028, #4029; as #3078, #3368, #3865). Each test
 * opens a dialog, closes it, changes what the mocked API answers (another
 * client's edit) and opens it again on the same query cache.
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
import type { DNSZone, IPAMTemplate, Subnet } from "@/lib/api";

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

const { AddAddressModal, CreateSubnetModal } = await import("./IPAMPage");
const { BulkAllocateModal } = await import("./BulkAllocateModal");
const { ApplyTemplateControl } = await import("../dhcp/CreateScopeModal");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

// The app's own default (queryClient.ts): a list read in the last 30 s is
// served from cache on mount unless the query asks otherwise.
const qc = () =>
  new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 30_000 } },
  });

/** Mount ``ui`` on ``client``; returns a closer (the dialog being cancelled). */
function mount(client: QueryClient, ui: ReactNode) {
  const r = render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  return () => r.unmount();
}

async function zoneSelect(label: string): Promise<HTMLSelectElement> {
  const field = (await screen.findByText(label, { selector: "label" }))
    .nextElementSibling as HTMLElement;
  return (field.querySelector("select") ?? field) as HTMLSelectElement;
}

async function control<T extends HTMLElement = HTMLSelectElement>(
  label: string,
): Promise<T> {
  return (await screen.findByText(label, { selector: "label" }))
    .nextElementSibling as T;
}

const zone = (id: string, name: string) =>
  ({ id, group_id: "g1", name, kind: "forward" }) as DNSZone;

/** The subnet's DNS and the group's zones, as another client left them. */
function dnsState(primary: string, additional: string[], zones: DNSZone[]) {
  answer("ipamApi", "getEffectiveSubnetDns", () =>
    Promise.resolve({
      dns_group_ids: ["g1"],
      dns_zone_id: primary,
      dns_additional_zone_ids: additional,
    }),
  );
  answer("dnsApi", "listZones", () => Promise.resolve(zones));
}

const z0 = zone("z0", "z0.example.");
const z1 = zone("z1", "z1.example.");
const z2 = zone("z2", "z2.example.");

describe("the zone dialogs follow the subnet's primary as stored now (#4028)", () => {
  it("Allocate IP opened again picks the new primary, not the first cached zone", async () => {
    answer("customFieldsApi", "list", () => Promise.resolve([]));
    answer("ipamApi", "getSubnet", () =>
      Promise.resolve({ id: "s", network: "10.0.0.0/24" }),
    );
    const client = qc();
    dnsState("z1", ["z0"], [z0, z1]);
    const close = mount(
      client,
      <AddAddressModal subnetId="s" onClose={() => {}} />,
    );
    await waitFor(async () =>
      expect((await zoneSelect("DNS Zone")).value).toBe("z1"),
    );
    close();

    dnsState("z2", ["z1", "z0"], [z0, z1, z2]);
    mount(client, <AddAddressModal subnetId="s" onClose={() => {}} />);
    await waitFor(async () =>
      expect((await zoneSelect("DNS Zone")).value).toBe("z2"),
    );
  });

  it("Bulk allocate opened again picks the new primary", async () => {
    const subnet = { id: "s", network: "10.0.0.0/24", name: "x" } as Subnet;
    const client = qc();
    dnsState("z1", ["z0"], [z0, z1]);
    const close = mount(
      client,
      <BulkAllocateModal subnet={subnet} onClose={() => {}} />,
    );
    await waitFor(async () =>
      expect((await control("Forward zone")).value).toBe("z1"),
    );
    close();

    dnsState("z2", ["z1", "z0"], [z0, z1, z2]);
    mount(client, <BulkAllocateModal subnet={subnet} onClose={() => {}} />);
    await waitFor(async () =>
      expect((await control("Forward zone")).value).toBe("z2"),
    );
  });
});

describe("the template dialogs apply the template as stored now (#4029)", () => {
  const tpl = (dhcp: string) =>
    ({
      id: "t",
      name: "T",
      description: "",
      applies_to: "subnet",
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

  it("New Subnet opened again applies the DHCP group the template holds now", async () => {
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
    answer("ipamApi", "listBlocks", () =>
      Promise.resolve([{ id: "b", space_id: "sp", network: "10.84.0.0/16" }]),
    );
    answer("customFieldsApi", "list", () => Promise.resolve([]));
    const ui = (
      <CreateSubnetModal spaceId="sp" defaultBlockId="b" onClose={() => {}} />
    );
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

  it("New DHCP Scope's Apply template merges the options the template holds now", async () => {
    const optTpl = (dns: string) => [
      {
        id: "ot",
        name: "OT",
        address_family: "ipv4",
        options: { "dns-servers": [dns] },
      },
    ];
    const onApply = vi.fn();
    const ui = (
      <ApplyTemplateControl groupId="g" currentOptions={[]} onApply={onApply} />
    );
    const client = qc();

    answer("dhcpApi", "listOptionTemplates", () =>
      Promise.resolve(optTpl("192.0.2.81")),
    );
    const close = mount(client, ui);
    const first = (await screen.findByLabelText(
      "Apply template",
    )) as HTMLSelectElement;
    await waitFor(() => expect(first.disabled).toBe(false));
    close();

    answer("dhcpApi", "listOptionTemplates", () =>
      Promise.resolve(optTpl("192.0.2.82")),
    );
    mount(client, ui);
    const second = (await screen.findByLabelText(
      "Apply template",
    )) as HTMLSelectElement;
    await waitFor(() => expect(second.disabled).toBe(false));
    fireEvent.change(second, { target: { value: "ot" } });
    expect(onApply).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(onApply.mock.calls[0][0])).toContain("192.0.2.82");
  });
});
