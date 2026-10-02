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
import type { CustomField, IPAddress } from "@/lib/api";

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
