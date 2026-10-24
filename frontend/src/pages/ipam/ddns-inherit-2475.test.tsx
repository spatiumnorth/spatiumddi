/**
 * @vitest-environment jsdom
 *
 * Subnet dialogs: the DDNS tab shows inheritance and an untouched Save keeps it (#2475).
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
import type { Subnet } from "@/lib/api";

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

const { CreateSubnetModal, EditSubnetModal } = await import("./IPAMPage");

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

const inherited = {
  enabled: true,
  hostname_policy: "always_generate",
  domain_override: null,
  ttl: null,
  source: "block",
  source_id: "blk-1",
  source_name: "ddns-block",
};

const subnet = {
  id: "sub-1",
  space_id: "sp-1",
  block_id: "blk-1",
  network: "10.1.0.0/24",
  name: "s",
  description: "",
  vlan_id: null,
  vxlan_id: null,
  gateway: null,
  status: "active",
  tags: {},
  custom_fields: {},
  utilization_percent: 0,
  allocated_ips: 0,
  total_ips: 254,
  ddns_enabled: true,
  ddns_inherit_settings: true,
} as unknown as Subnet;

function enabledBox(): HTMLInputElement {
  return screen
    .getByText("Enabled", { selector: "label" })
    .querySelector("input") as HTMLInputElement;
}
function inheritBox(): HTMLInputElement {
  return screen
    .getByText("Inherit from parent", { selector: "label" })
    .querySelector("input") as HTMLInputElement;
}

describe("Edit Subnet's DDNS tab (#2475)", () => {
  function edit(s: Subnet) {
    answer("ipamApi", "getEffectiveSubnetDdns", () =>
      Promise.resolve(inherited),
    );
    const updateSubnet = sink(s);
    answer("ipamApi", "updateSubnet", updateSubnet);
    open(<EditSubnetModal subnet={s} onClose={() => {}} />);
    return updateSubnet;
  }

  it("shows an inheriting subnet as inheriting, with the parent's setting", async () => {
    edit({ ...subnet, ddns_enabled: false });
    fireEvent.click(await screen.findByRole("button", { name: "DDNS" }));
    expect(inheritBox().checked).toBe(true);
    await screen.findByText(
      /Inheriting from block ddns-block: DDNS is enabled/,
    );
    expect(enabledBox().checked).toBe(true);
    expect(enabledBox().disabled).toBe(true);
    expect(
      (screen.getByLabelText(/^Hostname policy/) as HTMLSelectElement).value,
    ).toBe("always_generate");
  });

  it("an untouched Save keeps inheritance: no ddns_enabled is sent", async () => {
    const updateSubnet = edit(subnet);
    await press("Save");
    await waitFor(() => expect(updateSubnet).toHaveBeenCalledTimes(1));
    const body = updateSubnet.mock.calls[0][1] as Record<string, unknown>;
    expect(body.ddns_inherit_settings).toBe(true);
    expect(body).not.toHaveProperty("ddns_enabled");
  });

  it("opting out sends the subnet's own settings with inheritance off", async () => {
    const updateSubnet = edit({ ...subnet, ddns_enabled: false });
    fireEvent.click(await screen.findByRole("button", { name: "DDNS" }));
    fireEvent.click(inheritBox());
    expect(enabledBox().checked).toBe(false);
    await press("Save");
    await waitFor(() => expect(updateSubnet).toHaveBeenCalledTimes(1));
    expect(updateSubnet.mock.calls[0][1]).toMatchObject({
      ddns_inherit_settings: false,
      ddns_enabled: false,
    });
  });
});

describe("New Subnet's DDNS tab (#2475)", () => {
  it("shows the block's DDNS as inherited and creates a subnet that inherits it", async () => {
    answer("ipamApi", "listBlocks", () =>
      Promise.resolve([
        { id: "blk-1", space_id: "sp-1", network: "10.1.0.0/16" },
      ]),
    );
    answer("ipamApi", "listTemplates", () => Promise.resolve([]));
    answer("customFieldsApi", "list", () => Promise.resolve([]));
    answer("ipamApi", "getEffectiveBlockDdns", () =>
      Promise.resolve(inherited),
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
    fireEvent.change(await findControl("Network (CIDR)"), {
      target: { value: "10.1.20.0/24" },
    });
    fireEvent.click(await screen.findByRole("button", { name: "DDNS" }));
    await screen.findByText(
      /Inheriting from block ddns-block: DDNS is enabled/,
    );
    expect(enabledBox().checked).toBe(true);
    await press("Create");
    await waitFor(() => expect(createSubnet).toHaveBeenCalledTimes(1));
    const body = createSubnet.mock.calls[0][0] as Record<string, unknown>;
    expect(body.ddns_inherit_settings).toBe(true);
    expect(body).not.toHaveProperty("ddns_enabled");
  });
});
