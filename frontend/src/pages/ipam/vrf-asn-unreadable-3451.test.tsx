/**
 * @vitest-environment jsdom
 *
 * #3451 — Edit IP Space and Edit Block for a user who may not read VRFs or
 * ASNs. The row is linked to both; the pickers say so without listing them,
 * and a Save of an unrelated change sends only that change, so the links the
 * user cannot see are never cleared or rewritten.
 *
 * Every API call a dialog makes stays pending unless a test answers it.
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

const { EditSpaceModal, EditBlockModal } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

/** The IPAM / DNS / DHCP Editor shape: no read on vrf or manage_asns. */
function signInAsEditor() {
  const grants = ["ip_space", "ip_block", "subnet", "ip_address"].flatMap((t) =>
    ["read", "write", "delete"].map((action) => ({
      action,
      resource_type: t,
      resource_id: null,
    })),
  );
  answer("authApi", "myPermissions", () =>
    Promise.resolve({ is_superadmin: false, grants }),
  );
}

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

async function pickersShowTheLinks() {
  fireEvent.click(screen.getByRole("button", { name: "Networking" }));
  const vrf = (await screen.findByTitle(
    /cannot read VRFs/,
  )) as HTMLSelectElement;
  const asn = (await screen.findByTitle(
    /cannot read ASNs/,
  )) as HTMLSelectElement;
  for (const sel of [vrf, asn]) {
    expect(sel.disabled).toBe(true);
    expect(sel.selectedOptions[0].textContent).toBe(
      "Linked (not visible to your role)",
    );
  }
  // The VRFs page link is withheld from a user who may not read VRFs.
  expect(screen.queryByRole("link", { name: /Network → VRFs/ })).toBeNull();
}

async function save() {
  const button = screen.getByRole("button", {
    name: "Save",
  }) as HTMLButtonElement;
  await waitFor(() => expect(button.disabled).toBe(false));
  fireEvent.click(button);
}

describe("unreadable VRF / ASN links survive an unrelated Save (#3451)", () => {
  it("Edit IP Space sends only the changed description", async () => {
    signInAsEditor();
    const vrfList = vi.fn(() => Promise.resolve([]));
    const asnList = vi.fn(() => Promise.resolve({ items: [] }));
    answer("vrfsApi", "list", vrfList);
    answer("asnsApi", "list", asnList);
    const space = {
      id: "sp-1",
      name: "corp",
      description: "old",
      color: null,
      tags: {},
      vrf_id: "vrf-1",
      asn_id: "asn-1",
      customer_id: null,
    };
    const updateSpace = vi.fn((..._a: unknown[]) => Promise.resolve(space));
    answer("ipamApi", "getSpace", () => Promise.resolve(space));
    answer("ipamApi", "updateSpace", updateSpace);
    open(
      <EditSpaceModal
        space={space as never}
        onClose={() => {}}
        onDeleted={() => {}}
      />,
    );
    fireEvent.change(await screen.findByDisplayValue("old"), {
      target: { value: "new" },
    });
    await pickersShowTheLinks();
    await save();
    await waitFor(() => expect(updateSpace).toHaveBeenCalledTimes(1));
    expect(updateSpace.mock.calls[0][1]).toEqual({ description: "new" });
    expect(vrfList).not.toHaveBeenCalled();
    expect(asnList).not.toHaveBeenCalled();
  });

  it("Edit Block sends only the changed description", async () => {
    signInAsEditor();
    const vrfList = vi.fn(() => Promise.resolve([]));
    const asnList = vi.fn(() => Promise.resolve({ items: [] }));
    answer("vrfsApi", "list", vrfList);
    answer("asnsApi", "list", asnList);
    const block = {
      id: "b-1",
      space_id: "sp-1",
      parent_block_id: null,
      network: "10.98.0.0/16",
      name: "core",
      description: "old",
      tags: {},
      custom_fields: {},
      vrf_id: "vrf-1",
      asn_id: "asn-1",
      customer_id: null,
      site_id: null,
    };
    const updateBlock = vi.fn((..._a: unknown[]) => Promise.resolve(block));
    answer("ipamApi", "getBlock", () => Promise.resolve(block));
    answer("ipamApi", "updateBlock", updateBlock);
    open(<EditBlockModal block={block as never} onClose={() => {}} />);
    fireEvent.change(await screen.findByDisplayValue("old"), {
      target: { value: "new" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Networking" }));
    const vrf = (await screen.findByTitle(
      /cannot read VRFs/,
    )) as HTMLSelectElement;
    const asn = (await screen.findByTitle(
      /cannot read ASNs/,
    )) as HTMLSelectElement;
    for (const sel of [vrf, asn]) {
      expect(sel.disabled).toBe(true);
      expect(sel.selectedOptions[0].textContent).toBe(
        "Linked (not visible to your role)",
      );
    }
    await save();
    await waitFor(() => expect(updateBlock).toHaveBeenCalledTimes(1));
    expect(updateBlock.mock.calls[0][1]).toEqual({ description: "new" });
    expect(vrfList).not.toHaveBeenCalled();
    expect(asnList).not.toHaveBeenCalled();
  });
});
