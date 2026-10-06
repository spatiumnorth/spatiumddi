/**
 * @vitest-environment jsdom
 *
 * IPAM dialogs: what the form shows is what it sends (#1303-#1307).
 *
 * Each test opens the real dialog and leaves every pre-filled value alone,
 * the way a person accepts a form, then holds what the dialog SHOWS against
 * what it SENDS. Every API call a dialog makes stays pending unless a test
 * answers it, so nothing here depends on data it was not given.
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
import type { CustomField, IPAddress, IPAMTemplate } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
/** Per API object, the calls a test answers. Anything else stays pending. */
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

const {
  AddAddressModal,
  CreateBlockModal,
  CreateSubnetModal,
  EditAddressModal,
} = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

/** A spy that resolves with ``value`` and records what it was sent. */
function sink(value: unknown = {}) {
  return vi.fn((..._args: unknown[]) => Promise.resolve(value));
}

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The control a `<Field label>` wraps (the label has no `htmlFor`). */
function control<T extends HTMLElement = HTMLInputElement>(label: string): T {
  return screen.getByText(label, { selector: "label" }).nextElementSibling as T;
}

async function findControl<T extends HTMLElement = HTMLInputElement>(
  label: string,
): Promise<T> {
  return (await screen.findByText(label, { selector: "label" }))
    .nextElementSibling as T;
}

async function press(name: string) {
  const button = screen.getByRole("button", { name }) as HTMLButtonElement;
  await waitFor(() => expect(button.disabled).toBe(false));
  fireEvent.click(button);
}

function cf(
  over: Partial<CustomField> & Pick<CustomField, "name" | "label">,
): CustomField {
  return {
    id: `cf-${over.name}`,
    resource_type: "ip_address",
    field_type: "text",
    options: null,
    is_required: false,
    is_searchable: false,
    default_value: null,
    display_order: 0,
    description: "",
    ...over,
  };
}

const STAMP = "2026-10-02T00:00:00Z";

function address(over: Partial<IPAddress> = {}): IPAddress {
  return {
    id: "ip-1",
    subnet_id: "sub-1",
    address: "10.85.20.41",
    status: "allocated",
    role: null,
    hostname: "web01",
    fqdn: null,
    description: "",
    mac_address: null,
    tags: {},
    custom_fields: {},
    created_at: STAMP,
    modified_at: STAMP,
    ...over,
  };
}

/** Allocate IP on an IPv4 subnet whose next free address is 10.0.0.2. */
function allocateIp(defs: CustomField[] = []) {
  answer("customFieldsApi", "list", () => Promise.resolve(defs));
  answer("ipamApi", "previewNextIp", () =>
    Promise.resolve({ address: "10.0.0.2", strategy: "sequential" }),
  );
  const nextAddress = sink({ id: "ip-new", address: "10.0.0.2" });
  answer("ipamApi", "nextAddress", nextAddress);
  open(<AddAddressModal subnetId="sub-1" onClose={() => {}} />);
  return nextAddress;
}

// ── #1303 — a custom field's Default Value ──────────────────────────────────

describe("a custom field's Default Value is what the dialog sends (#1303)", () => {
  it("Allocate IP sends the text and select defaults it shows", async () => {
    const nextAddress = allocateIp([
      cf({ name: "owner", label: "Owner team", default_value: "netops" }),
      cf({
        name: "tier",
        label: "Tier",
        field_type: "select",
        options: ["gold", "silver"],
        default_value: "silver",
      }),
    ]);

    expect((await findControl("Owner team")).value).toBe("netops");
    expect(control<HTMLSelectElement>("Tier").value).toBe("silver");
    fireEvent.change(screen.getByPlaceholderText("Required"), {
      target: { value: "web01" },
    });
    await press("Allocate");

    await waitFor(() => expect(nextAddress).toHaveBeenCalledTimes(1));
    expect(nextAddress.mock.calls[0][1]).toMatchObject({
      custom_fields: { owner: "netops", tier: "silver" },
    });
  });

  it('Allocate IP shows a boolean default of "false" unchecked and sends false', async () => {
    const nextAddress = allocateIp([
      cf({
        name: "managed",
        label: "Managed",
        field_type: "boolean",
        default_value: "false",
      }),
      cf({
        name: "monitored",
        label: "Monitored",
        field_type: "boolean",
        default_value: "true",
      }),
    ]);

    expect((await findControl("Managed")).checked).toBe(false);
    expect(control("Monitored").checked).toBe(true);
    fireEvent.change(screen.getByPlaceholderText("Required"), {
      target: { value: "web01" },
    });
    await press("Allocate");

    await waitFor(() => expect(nextAddress).toHaveBeenCalledTimes(1));
    expect(nextAddress.mock.calls[0][1]).toMatchObject({
      custom_fields: { managed: false, monitored: true },
    });
  });

  it("an operator's own value replaces the default", async () => {
    const nextAddress = allocateIp([
      cf({ name: "owner", label: "Owner team", default_value: "netops" }),
    ]);

    fireEvent.change(await findControl("Owner team"), {
      target: { value: "helpdesk" },
    });
    fireEvent.change(screen.getByPlaceholderText("Required"), {
      target: { value: "web01" },
    });
    await press("Allocate");

    await waitFor(() => expect(nextAddress).toHaveBeenCalledTimes(1));
    expect(nextAddress.mock.calls[0][1]).toMatchObject({
      custom_fields: { owner: "helpdesk" },
    });
  });

  it("New Subnet sends the default it shows", async () => {
    answer("ipamApi", "listBlocks", () =>
      Promise.resolve([
        { id: "blk-1", space_id: "sp-1", network: "10.84.0.0/16" },
      ]),
    );
    answer("ipamApi", "listTemplates", () => Promise.resolve([]));
    answer("customFieldsApi", "list", () =>
      Promise.resolve([
        cf({
          name: "site",
          label: "Site code",
          resource_type: "subnet",
          default_value: "hq",
        }),
      ]),
    );
    const createSubnet = sink({ id: "sub-new" });
    answer("ipamApi", "createSubnet", createSubnet);
    open(
      <CreateSubnetModal
        spaceId="sp-1"
        defaultBlockId="blk-1"
        onClose={() => {}}
      />,
    );

    expect((await findControl("Site code")).value).toBe("hq");
    fireEvent.change(control("Network (CIDR)"), {
      target: { value: "10.84.20.0/24" },
    });
    await press("Create");

    await waitFor(() => expect(createSubnet).toHaveBeenCalledTimes(1));
    expect(createSubnet.mock.calls[0][0]).toMatchObject({
      custom_fields: { site: "hq" },
    });
  });

  it("New IP Block sends the default it shows", async () => {
    answer("ipamApi", "listBlocks", () => Promise.resolve([]));
    answer("ipamApi", "listTemplates", () => Promise.resolve([]));
    answer("customFieldsApi", "list", () =>
      Promise.resolve([
        cf({
          name: "owner",
          label: "Owner team",
          resource_type: "ip_block",
          default_value: "neteng",
        }),
      ]),
    );
    const createBlock = sink({ id: "blk-new" });
    answer("ipamApi", "createBlock", createBlock);
    open(<CreateBlockModal spaceId="sp-1" onClose={() => {}} />);

    expect((await findControl("Owner team")).value).toBe("neteng");
    fireEvent.change(control("Network (CIDR)"), {
      target: { value: "10.85.0.0/16" },
    });
    await press("Create Block");

    await waitFor(() => expect(createBlock).toHaveBeenCalledTimes(1));
    expect(createBlock.mock.calls[0][0]).toMatchObject({
      custom_fields: { owner: "neteng" },
    });
  });

  it("Edit address shows only what the address is stored with", async () => {
    answer("customFieldsApi", "list", () =>
      Promise.resolve([
        cf({ name: "owner", label: "Owner team", default_value: "helpdesk" }),
        cf({
          name: "managed",
          label: "Managed",
          field_type: "boolean",
          default_value: "true",
        }),
        cf({ name: "legacy", label: "Legacy", field_type: "boolean" }),
      ]),
    );
    const updateAddress = sink(address());
    answer("ipamApi", "updateAddress", updateAddress);
    // Never had owner or managed; legacy was stored as the string "false".
    open(
      <EditAddressModal
        address={address({ custom_fields: { legacy: "false" } })}
        onClose={() => {}}
      />,
    );

    expect((await findControl("Owner team")).value).toBe("");
    expect(control("Managed").checked).toBe(false);
    expect(control("Legacy").checked).toBe(false);
    await press("Save");

    await waitFor(() => expect(updateAddress).toHaveBeenCalledTimes(1));
    expect(
      (updateAddress.mock.calls[0][1] as { custom_fields: unknown })
        .custom_fields,
    ).toEqual({ legacy: "false" });
  });
});

// ── #1304 — a template picked in New Subnet / New IP Block ───────────────────

function template(
  over: Partial<IPAMTemplate> & Pick<IPAMTemplate, "id" | "applies_to">,
): IPAMTemplate {
  return {
    name: `template ${over.id}`,
    description: "",
    tags: {},
    custom_fields: {},
    dns_group_id: null,
    dns_zone_id: null,
    dns_additional_zone_ids: null,
    dhcp_group_id: null,
    ddns_enabled: false,
    ddns_hostname_policy: "client_or_generated",
    ddns_domain_override: null,
    ddns_ttl: null,
    child_layout: null,
    applied_count: 0,
    created_at: STAMP,
    modified_at: STAMP,
    ...over,
  };
}

/** The DNS and DHCP server groups (and the zone) a template can name. */
function serverGroups() {
  answer("dhcpApi", "listGroups", () =>
    Promise.resolve([{ id: "dhcp-grp-1", name: "campus" }]),
  );
  answer("dnsApi", "listGroups", () =>
    Promise.resolve([{ id: "dns-grp-1", name: "corp" }]),
  );
  answer("dnsApi", "listZones", () =>
    Promise.resolve([
      { id: "zone-1", name: "corp.example.", group_id: "dns-grp-1" },
    ]),
  );
}

function newSubnet(tpl: IPAMTemplate, defs: CustomField[] = []) {
  answer("ipamApi", "listBlocks", () =>
    Promise.resolve([
      { id: "blk-1", space_id: "sp-1", network: "10.84.0.0/16" },
    ]),
  );
  answer("ipamApi", "listTemplates", () => Promise.resolve([tpl]));
  answer("customFieldsApi", "list", () => Promise.resolve(defs));
  serverGroups();
  const createSubnet = sink({ id: "sub-new" });
  answer("ipamApi", "createSubnet", createSubnet);
  open(
    <CreateSubnetModal
      spaceId="sp-1"
      defaultBlockId="blk-1"
      onClose={() => {}}
    />,
  );
  return createSubnet;
}

async function pickTemplate(id: string) {
  fireEvent.change(
    await findControl<HTMLSelectElement>("Apply template (optional)"),
    { target: { value: id } },
  );
}

function tab(name: string) {
  fireEvent.click(screen.getByRole("button", { name }));
}

/** The `<select>` under a section's caption (`<p>DHCP Server Group</p>`). */
function selectUnder(caption: string): HTMLSelectElement {
  return screen.getByText(caption).nextElementSibling as HTMLSelectElement;
}

describe("a template picked in the dialog is what the dialog sends (#1304)", () => {
  const SITE = cf({
    name: "site",
    label: "Site code",
    resource_type: "subnet",
  });

  it("New Subnet shows and sends the template's custom field and DDNS", async () => {
    const createSubnet = newSubnet(
      template({
        id: "tpl-1",
        applies_to: "subnet",
        custom_fields: { site: "from-template" },
        ddns_enabled: true,
        ddns_hostname_policy: "always_generate",
        ddns_ttl: 120,
      }),
      [SITE],
    );

    await pickTemplate("tpl-1");
    expect((await findControl("Site code")).value).toBe("from-template");
    tab("DDNS");
    expect((screen.getByLabelText("Enabled") as HTMLInputElement).checked).toBe(
      true,
    );
    expect(
      (screen.getByLabelText(/^Hostname policy/) as HTMLSelectElement).value,
    ).toBe("always_generate");
    fireEvent.change(control("Network (CIDR)"), {
      target: { value: "10.84.20.0/24" },
    });
    await press("Create");

    await waitFor(() => expect(createSubnet).toHaveBeenCalledTimes(1));
    expect(createSubnet.mock.calls[0][0]).toMatchObject({
      template_id: "tpl-1",
      custom_fields: { site: "from-template" },
      ddns_enabled: true,
      ddns_hostname_policy: "always_generate",
      ddns_ttl: 120,
    });
  });

  it("New Subnet shows and sends the template's DNS and DHCP groups", async () => {
    const createSubnet = newSubnet(
      template({
        id: "tpl-2",
        applies_to: "subnet",
        dns_group_id: "dns-grp-1",
        dns_zone_id: "zone-1",
        dhcp_group_id: "dhcp-grp-1",
      }),
    );

    await pickTemplate("tpl-2");
    tab("DHCP");
    expect(
      (screen.getByLabelText("Inherit from parent") as HTMLInputElement)
        .checked,
    ).toBe(false);
    await waitFor(() =>
      expect(selectUnder("DHCP Server Group").value).toBe("dhcp-grp-1"),
    );
    tab("DNS");
    expect(
      (screen.getByLabelText("Inherit from parent") as HTMLInputElement)
        .checked,
    ).toBe(false);
    await waitFor(() =>
      expect(selectUnder("DNS Server Group").value).toBe("dns-grp-1"),
    );
    await waitFor(() =>
      expect(selectUnder("Primary Zone").value).toBe("zone-1"),
    );
    fireEvent.change(control("Network (CIDR)"), {
      target: { value: "10.84.21.0/24" },
    });
    await press("Create");

    await waitFor(() => expect(createSubnet).toHaveBeenCalledTimes(1));
    expect(createSubnet.mock.calls[0][0]).toMatchObject({
      template_id: "tpl-2",
      dns_inherit_settings: false,
      dns_group_ids: ["dns-grp-1"],
      dns_zone_id: "zone-1",
      dhcp_inherit_settings: false,
      dhcp_server_group_id: "dhcp-grp-1",
    });
  });

  it("what the operator changes after picking the template wins", async () => {
    const createSubnet = newSubnet(
      template({
        id: "tpl-1",
        applies_to: "subnet",
        custom_fields: { site: "from-template" },
        ddns_enabled: true,
      }),
      [SITE],
    );

    await pickTemplate("tpl-1");
    fireEvent.change(await findControl("Site code"), {
      target: { value: "branch-7" },
    });
    tab("DDNS");
    fireEvent.click(screen.getByLabelText("Enabled"));
    fireEvent.change(control("Network (CIDR)"), {
      target: { value: "10.84.22.0/24" },
    });
    await press("Create");

    await waitFor(() => expect(createSubnet).toHaveBeenCalledTimes(1));
    expect(createSubnet.mock.calls[0][0]).toMatchObject({
      custom_fields: { site: "branch-7" },
      ddns_enabled: false,
    });
  });

  it("New IP Block shows and sends the template's custom field and DHCP group", async () => {
    answer("ipamApi", "listBlocks", () => Promise.resolve([]));
    answer("ipamApi", "listTemplates", () =>
      Promise.resolve([
        template({
          id: "btpl-1",
          applies_to: "block",
          custom_fields: { owner: "neteng" },
          dhcp_group_id: "dhcp-grp-1",
        }),
      ]),
    );
    answer("customFieldsApi", "list", () =>
      Promise.resolve([
        cf({ name: "owner", label: "Owner team", resource_type: "ip_block" }),
      ]),
    );
    serverGroups();
    const createBlock = sink({ id: "blk-new" });
    answer("ipamApi", "createBlock", createBlock);
    open(<CreateBlockModal spaceId="sp-1" onClose={() => {}} />);

    await pickTemplate("btpl-1");
    expect((await findControl("Owner team")).value).toBe("neteng");
    tab("DHCP");
    expect(
      (screen.getByLabelText("Inherit from parent") as HTMLInputElement)
        .checked,
    ).toBe(false);
    await waitFor(() =>
      expect(selectUnder("DHCP Server Group").value).toBe("dhcp-grp-1"),
    );
    fireEvent.change(control("Network (CIDR)"), {
      target: { value: "10.85.0.0/16" },
    });
    await press("Create Block");

    await waitFor(() => expect(createBlock).toHaveBeenCalledTimes(1));
    expect(createBlock.mock.calls[0][0]).toMatchObject({
      template_id: "btpl-1",
      custom_fields: { owner: "neteng" },
      dhcp_inherit_settings: false,
      dhcp_server_group_id: "dhcp-grp-1",
    });
  });
});
// ── #1305 — the status and role an address is stored with ────────────────────

describe("Edit address shows the status and role it is stored with (#1305)", () => {
  function editAddress(row: IPAddress) {
    answer("customFieldsApi", "list", () => Promise.resolve([]));
    const updateAddress = sink(row);
    answer("ipamApi", "updateAddress", updateAddress);
    open(<EditAddressModal address={row} onClose={() => {}} />);
    return updateAddress;
  }

  it("a TLS-serving role (web, api, lb) is shown and offered", async () => {
    const updateAddress = editAddress(address({ role: "web" }));

    const role = control<HTMLSelectElement>("Role");
    expect(role.value).toBe("web");
    expect([...role.options].map((o) => o.value)).toEqual(
      expect.arrayContaining(["web", "api", "lb"]),
    );
    await press("Save");

    await waitFor(() => expect(updateAddress).toHaveBeenCalledTimes(1));
    expect(updateAddress.mock.calls[0][1]).toMatchObject({ role: "web" });
  });

  it("an integration-owned status is shown as itself, not as available", async () => {
    const updateAddress = editAddress(address({ status: "docker-container" }));

    expect(control<HTMLSelectElement>("Status").value).toBe("docker-container");
    await press("Save");

    await waitFor(() => expect(updateAddress).toHaveBeenCalledTimes(1));
    expect(updateAddress.mock.calls[0][1]).toMatchObject({
      status: "docker-container",
    });
  });
});
// ── #1306 — the DHCP Scope picker ────────────────────────────────────────────

describe("Allocate IP shows a DHCP Scope only where it uses one (#1306)", () => {
  function allocateWithScope() {
    answer("dhcpApi", "listScopesBySubnet", () =>
      Promise.resolve([
        {
          id: "scope-1",
          subnet_id: "sub-1",
          group_id: "dhcp-grp-1",
          name: "staff",
        },
      ]),
    );
    answer("dhcpApi", "listPools", () => Promise.resolve([]));
    const createStatic = sink({ id: "static-1" });
    answer("dhcpApi", "createStatic", createStatic);
    const nextAddress = allocateIp();
    return { nextAddress, createStatic };
  }

  it('status "dhcp" shows no scope, because the request carries none', async () => {
    const { nextAddress, createStatic } = allocateWithScope();
    const status = await findControl<HTMLSelectElement>("Type / Status");

    // Positive control first: the dialog has the subnet's scope, and offers
    // it for a reservation. Only then is its absence below the dialog's
    // own decision rather than a scope list still loading.
    fireEvent.change(status, { target: { value: "static_dhcp" } });
    await waitFor(() =>
      expect(control<HTMLSelectElement>("DHCP Scope").value).toBe("scope-1"),
    );
    fireEvent.change(status, { target: { value: "dhcp" } });
    expect(screen.queryByText("DHCP Scope", { selector: "label" })).toBeNull();
    fireEvent.change(screen.getByPlaceholderText("Required"), {
      target: { value: "web01" },
    });
    await press("Allocate");

    await waitFor(() => expect(nextAddress).toHaveBeenCalledTimes(1));
    expect(nextAddress.mock.calls[0][1]).toMatchObject({ status: "dhcp" });
    expect(createStatic).not.toHaveBeenCalled();
  });

  it("static_dhcp no longer chains a DHCP call — the server syncs the reservation (#1628)", async () => {
    const { nextAddress, createStatic } = allocateWithScope();

    fireEvent.change(await findControl<HTMLSelectElement>("Type / Status"), {
      target: { value: "static_dhcp" },
    });
    await waitFor(() =>
      expect(control<HTMLSelectElement>("DHCP Scope").value).toBe("scope-1"),
    );
    fireEvent.change(control("MAC Address"), {
      target: { value: "aa:bb:cc:dd:ee:ff" },
    });
    fireEvent.change(screen.getByPlaceholderText("Required"), {
      target: { value: "web01" },
    });
    await press("Allocate");

    await waitFor(() => expect(nextAddress).toHaveBeenCalledTimes(1));
    expect(nextAddress.mock.calls[0][1]).toMatchObject({
      status: "static_dhcp",
      mac_address: "aa:bb:cc:dd:ee:ff",
    });
    expect(createStatic).not.toHaveBeenCalled();
  });
});
// ── #1307 — "Next available" on an IPv6 subnet ───────────────────────────────

describe("Allocate IP names as next available only what it allocates (#1307)", () => {
  it("an IPv6 subnet that picks at random names no address", async () => {
    answer("customFieldsApi", "list", () => Promise.resolve([]));
    // What the preview answers for a subnet whose ipv6_allocation_policy is
    // random: a free candidate, and the strategy that drew it. The commit
    // draws its own.
    answer("ipamApi", "previewNextIp", () =>
      Promise.resolve({ address: "fd86:929:20::a3f1", strategy: "random" }),
    );
    const nextAddress = sink({ id: "ip-new", address: "fd86:929:20::77c2" });
    answer("ipamApi", "nextAddress", nextAddress);
    open(<AddAddressModal subnetId="sub-v6" onClose={() => {}} />);

    expect(await screen.findByText(/picked when you allocate/)).toBeTruthy();
    expect(screen.queryByText("fd86:929:20::a3f1")).toBeNull();
    fireEvent.change(screen.getByPlaceholderText("Required"), {
      target: { value: "web01" },
    });
    await press("Allocate");

    await waitFor(() => expect(nextAddress).toHaveBeenCalledTimes(1));
  });

  it("a subnet that allocates in order names the address it allocates", async () => {
    allocateIp();

    expect(await screen.findByText("10.0.0.2")).toBeTruthy();
    expect(screen.queryByText(/picked when you allocate/)).toBeNull();
  });
});
