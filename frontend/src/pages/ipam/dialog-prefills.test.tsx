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
import type { CustomField, DNSZone, IPAddress, IPAMTemplate } from "@/lib/api";

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
    const row = address({ custom_fields: { legacy: "false" } });
    answer("ipamApi", "getAddress", () => Promise.resolve(row));
    open(<EditAddressModal address={row} onClose={() => {}} />);

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
    answer("ipamApi", "getAddress", () => Promise.resolve(row));
    open(<EditAddressModal address={row} onClose={() => {}} />);
    return updateAddress;
  }

  it("a TLS-serving role (web, api, lb) is shown and offered", async () => {
    const updateAddress = editAddress(address({ role: "web" }));

    const role = await findControl<HTMLSelectElement>("Role");
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

    expect((await findControl<HTMLSelectElement>("Status")).value).toBe(
      "docker-container",
    );
    await press("Save");

    await waitFor(() => expect(updateAddress).toHaveBeenCalledTimes(1));
    expect(updateAddress.mock.calls[0][1]).toMatchObject({
      status: "docker-container",
    });
  });
});
// ── #1306 / #1629 — the DHCP Scope picker is gone ────────────────────────────

describe("Allocate IP has no DHCP Scope picker — the server picks the scope (#1306, #1629)", () => {
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

  it("no status shows a scope picker, because the request carries none", async () => {
    const { nextAddress, createStatic } = allocateWithScope();
    const status = await findControl<HTMLSelectElement>("Type / Status");

    // The subnet HAS a scope (answered above, and the pools query that
    // rides on it resolves) — the picker is absent by decision, not
    // because the scope list is still loading. Since #1628 the server
    // syncs the reservation onto the sole matching scope itself, and
    // #1629 removed the picker the walk found no request carrying.
    fireEvent.change(status, { target: { value: "static_dhcp" } });
    expect(screen.queryByText("DHCP Scope", { selector: "label" })).toBeNull();
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
    expect(screen.queryByText("DHCP Scope", { selector: "label" })).toBeNull();
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

// ── #1422 — Allocate IP's Type / Status ─────────────────────────────────────

/** What both of Allocate IP's requests accept as ``status``:
 *  ``IP_STATUSES_OPERATOR_SETTABLE | {"dhcp"}`` (backend
 *  ``models/ipam.py``; ``NextIPRequest`` / ``IPAddressCreate``
 *  ``validate_status`` in ``api/v1/ipam/router.py``). */
const CREATE_STATUSES = [
  "available",
  "allocated",
  "reserved",
  "static_dhcp",
  "deprecated",
  "orphan",
  "dhcp",
];

describe("Allocate IP offers only the statuses its requests accept (#1422)", () => {
  async function offered(): Promise<string[]> {
    allocateIp();
    const status = await findControl<HTMLSelectElement>("Type / Status");
    return Array.from(status.options).map((o) => o.value);
  }

  it("offers no status both of its requests refuse", async () => {
    // "Next available" posts /subnets/{id}/next and "Specific IP" posts
    // /subnets/{id}/addresses; both answer 422 to anything else, so an
    // offered "discovered" (integration-owned) could only ever fail.
    const statuses = await offered();
    expect(statuses.length).toBeGreaterThan(0);
    expect(statuses.filter((s) => !CREATE_STATUSES.includes(s))).toEqual([]);
  });

  it("still offers every status an operator allocates with", async () => {
    const statuses = await offered();
    expect(statuses).toEqual(
      expect.arrayContaining([
        "allocated",
        "reserved",
        "dhcp",
        "static_dhcp",
        "available",
        "deprecated",
      ]),
    );
    expect(control<HTMLSelectElement>("Type / Status").value).toBe("allocated");
  });
});

// ── #2469 — the DNS Zone pre-fill does not latch on the first group to answer ─
describe("Allocate IP pre-fills the primary zone whichever DNS group answers first (#2469)", () => {
  const zp = { id: "zp", group_id: "gP", name: "p.test.", kind: "forward" };
  const zs = { id: "zs", group_id: "gS", name: "s.test.", kind: "forward" };

  function allocateTwoGroups() {
    let releasePrimary: (v: unknown) => void = () => {};
    const held = new Promise((r) => (releasePrimary = r));
    answer("ipamApi", "getEffectiveSubnetDns", () =>
      Promise.resolve({
        dns_group_ids: ["gS", "gP"],
        dns_zone_id: "zp",
        dns_additional_zone_ids: ["zs"],
      }),
    );
    answer("dnsApi", "listZones", (g: unknown) =>
      g === "gP" ? held : Promise.resolve([zs]),
    );
    const nextAddress = allocateIp();
    return { nextAddress, releasePrimary: () => releasePrimary([zp]) };
  }

  it("settles on the primary once its group answers, and sends it", async () => {
    const { nextAddress, releasePrimary } = allocateTwoGroups();
    fireEvent.change(screen.getByPlaceholderText("Required"), {
      target: { value: "web01" },
    });
    await screen.findByText("DNS Zone", { selector: "label" });
    releasePrimary();
    await waitFor(() =>
      expect(control("DNS Zone").querySelector("select")?.value).toBe("zp"),
    );
    await press("Allocate");
    await waitFor(() => expect(nextAddress).toHaveBeenCalledTimes(1));
    expect(nextAddress.mock.calls[0][1]).toMatchObject({ dns_zone_id: "zp" });
  });

  it("an operator's own pick is not overridden when the primary lands", async () => {
    const { nextAddress, releasePrimary } = allocateTwoGroups();
    fireEvent.change(screen.getByPlaceholderText("Required"), {
      target: { value: "web01" },
    });
    await screen.findByText("DNS Zone", { selector: "label" });
    // Only the additional zone is on offer so far: a static line, not a
    // picker. Land the primary, then choose the additional zone.
    releasePrimary();
    const picker = await waitFor(() => {
      const s = control("DNS Zone").querySelector("select");
      expect(s).toBeTruthy();
      return s as HTMLSelectElement;
    });
    fireEvent.change(picker, { target: { value: "zs" } });
    await press("Allocate");
    await waitFor(() => expect(nextAddress).toHaveBeenCalledTimes(1));
    expect(nextAddress.mock.calls[0][1]).toMatchObject({ dns_zone_id: "zs" });
  });
});

// ── #2468 — Edit address names the zone its record is in ─────────────────────
describe("Edit address names the zone its record is in (#2468)", () => {
  function zone(id: string, name: string, group = "g1"): DNSZone {
    return { id, group_id: group, name, kind: "forward" } as DNSZone;
  }
  const A = zone("za", "a.test.");
  const B = zone("zb", "b.test.", "g2");
  const C = zone("zc", "c.test.");

  async function zonePicker(): Promise<HTMLSelectElement> {
    await findControl("DNS Zone");
    return waitFor(() => {
      const picker = control("DNS Zone").querySelector("select");
      expect(picker).toBeTruthy();
      return picker as HTMLSelectElement;
    });
  }

  function editStored(subnetZones: DNSZone[]) {
    answer("customFieldsApi", "list", () => Promise.resolve([]));
    answer("ipamApi", "getEffectiveSubnetDns", () =>
      Promise.resolve({
        dns_group_ids: ["g1"],
        dns_zone_id: "za",
        dns_additional_zone_ids: subnetZones
          .filter((z) => z.id !== "za")
          .map((z) => z.id),
      }),
    );
    answer("dnsApi", "listGroups", () =>
      Promise.resolve([{ id: "g1" }, { id: "g2" }]),
    );
    answer("dnsApi", "listZones", (g: unknown) =>
      Promise.resolve(g === "g1" ? subnetZones : [B]),
    );
    const updateAddress = sink(address());
    answer("ipamApi", "updateAddress", updateAddress);
    const row = address({ forward_zone_id: "zb" });
    answer("ipamApi", "getAddress", () => Promise.resolve(row));
    open(<EditAddressModal address={row} onClose={() => {}} />);
    return updateAddress;
  }

  it("with two zones left on the subnet it selects the stored zone, not None", async () => {
    editStored([A, C]);
    const select = await zonePicker();
    await waitFor(() => expect(select.value).toBe("zb"));
    expect(
      [...select.options].some(
        (o) => o.value === "zb" && /b\.test/.test(o.text),
      ),
    ).toBe(true);
  });

  it("with one zone left it names the stored zone beside the picker", async () => {
    editStored([A]);
    const select = await zonePicker();
    await waitFor(() => expect(select.value).toBe("zb"));
  });

  it("an untouched Save still leaves the zone alone", async () => {
    const updateAddress = editStored([A, C]);
    const select = await zonePicker();
    await waitFor(() => expect(select.value).toBe("zb"));
    await press("Save");
    await waitFor(() => expect(updateAddress).toHaveBeenCalledTimes(1));
    expect(
      (updateAddress.mock.calls[0][1] as { dns_zone_id?: string }).dns_zone_id,
    ).toBeUndefined();
  });
});

// ── #2466 — Allocate IP's DNS Zone "None" ────────────────────────────────────

describe('Allocate IP\'s DNS Zone "None" sends an explicit no-zone (#2466)', () => {
  function allocateWithZones() {
    answer("ipamApi", "getEffectiveSubnetDns", () =>
      Promise.resolve({
        dns_group_ids: ["g1"],
        dns_zone_id: "z1",
        dns_additional_zone_ids: ["z2"],
        inherited_from_block_id: null,
      }),
    );
    answer("dnsApi", "listZones", () =>
      Promise.resolve([
        { id: "z1", name: "a.example.", zone_type: "primary" },
        { id: "z2", name: "b.example.", zone_type: "primary" },
      ]),
    );
    return allocateIp();
  }

  it("None goes out as dns_zone_id: '' (absent would mean the subnet's zone)", async () => {
    const nextAddress = allocateWithZones();
    const zone = (await findControl<HTMLDivElement>("DNS Zone")).querySelector(
      "select",
    ) as HTMLSelectElement;
    await waitFor(() => expect(zone.value).toBe("z1"));
    fireEvent.change(zone, { target: { value: "" } });
    fireEvent.change(screen.getByPlaceholderText("Required"), {
      target: { value: "web01" },
    });
    await press("Allocate");

    await waitFor(() => expect(nextAddress).toHaveBeenCalledTimes(1));
    expect(nextAddress.mock.calls[0][1]).toMatchObject({ dns_zone_id: "" });
  });

  it("a chosen zone still goes out by id", async () => {
    const nextAddress = allocateWithZones();
    const zone = (await findControl<HTMLDivElement>("DNS Zone")).querySelector(
      "select",
    ) as HTMLSelectElement;
    await waitFor(() => expect(zone.value).toBe("z1"));
    fireEvent.change(screen.getByPlaceholderText("Required"), {
      target: { value: "web01" },
    });
    await press("Allocate");

    await waitFor(() => expect(nextAddress).toHaveBeenCalledTimes(1));
    expect(nextAddress.mock.calls[0][1]).toMatchObject({ dns_zone_id: "z1" });
  });
});

// ── #2472 — a forward zone whose name contains "arpa" is offered ─────────────
describe("the zone pickers tell reverse zones by suffix, not by substring (#2472)", () => {
  const z = (id: string, name: string) =>
    ({ id, group_id: "g1", name, kind: "forward" }) as DNSZone;
  const zones = [
    z("zp", "plain.test."),
    z("zs", "scarpa.test."),
    z("zr", "5.10.in-addr.arpa."),
    z("z6", "8.b.d.0.1.0.0.2.ip6.arpa."),
  ];

  function dnsAnswers() {
    answer("ipamApi", "getEffectiveSubnetDns", () =>
      Promise.resolve({
        dns_group_ids: ["g1"],
        dns_zone_id: null,
        dns_additional_zone_ids: [],
      }),
    );
    answer("dnsApi", "listZones", () => Promise.resolve(zones));
  }

  async function offered(): Promise<string[]> {
    await findControl("DNS Zone");
    const picker = await waitFor(() => {
      const s = control("DNS Zone").querySelector("select");
      expect(s).toBeTruthy();
      return s as HTMLSelectElement;
    });
    return [...picker.options].map((o) => o.value).filter(Boolean);
  }

  it("Allocate IP offers both forward zones and no reverse zone", async () => {
    dnsAnswers();
    allocateIp();
    expect(await offered()).toEqual(["zp", "zs"]);
  });

  it("Edit address offers both forward zones and no reverse zone", async () => {
    dnsAnswers();
    answer("customFieldsApi", "list", () => Promise.resolve([]));
    const row = address();
    answer("ipamApi", "getAddress", () => Promise.resolve(row));
    open(<EditAddressModal address={row} onClose={() => {}} />);
    expect(await offered()).toEqual(["zp", "zs"]);
  });
});

// ── #2466 — Allocate IP's DNS Zone "None" ────────────────────────────────────

describe('Allocate IP\'s DNS Zone "None" sends an explicit no-zone (#2466)', () => {
  function allocateWithZones() {
    answer("ipamApi", "getEffectiveSubnetDns", () =>
      Promise.resolve({
        dns_group_ids: ["g1"],
        dns_zone_id: "z1",
        dns_additional_zone_ids: ["z2"],
        inherited_from_block_id: null,
      }),
    );
    answer("dnsApi", "listZones", () =>
      Promise.resolve([
        { id: "z1", name: "a.example.", zone_type: "primary" },
        { id: "z2", name: "b.example.", zone_type: "primary" },
      ]),
    );
    return allocateIp();
  }

  it("None goes out as dns_zone_id: '' (absent would mean the subnet's zone)", async () => {
    const nextAddress = allocateWithZones();
    const zone = (await findControl<HTMLDivElement>("DNS Zone")).querySelector(
      "select",
    ) as HTMLSelectElement;
    await waitFor(() => expect(zone.value).toBe("z1"));
    fireEvent.change(zone, { target: { value: "" } });
    fireEvent.change(screen.getByPlaceholderText("Required"), {
      target: { value: "web01" },
    });
    await press("Allocate");

    await waitFor(() => expect(nextAddress).toHaveBeenCalledTimes(1));
    expect(nextAddress.mock.calls[0][1]).toMatchObject({ dns_zone_id: "" });
  });

  it("a chosen zone still goes out by id", async () => {
    const nextAddress = allocateWithZones();
    const zone = (await findControl<HTMLDivElement>("DNS Zone")).querySelector(
      "select",
    ) as HTMLSelectElement;
    await waitFor(() => expect(zone.value).toBe("z1"));
    fireEvent.change(screen.getByPlaceholderText("Required"), {
      target: { value: "web01" },
    });
    await press("Allocate");

    await waitFor(() => expect(nextAddress).toHaveBeenCalledTimes(1));
    expect(nextAddress.mock.calls[0][1]).toMatchObject({ dns_zone_id: "z1" });
  });
});
