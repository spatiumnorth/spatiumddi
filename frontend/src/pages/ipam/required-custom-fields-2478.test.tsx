/**
 * @vitest-environment jsdom
 *
 * Required custom fields in the block and subnet dialogs (#2478).
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
import type { CustomField, IPBlock } from "@/lib/api";

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

const { CreateBlockModal, CreateSubnetModal, EditBlockModal } =
  await import("./IPAMPage");

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
    resource_type: "subnet",
    field_type: "text",
    options: null,
    is_required: true,
    is_searchable: false,
    default_value: null,
    display_order: 0,
    description: "",
    ...over,
  };
}

const TIER = cf({
  name: "tier",
  label: "Tier",
  resource_type: "ip_block",
  field_type: "select",
  options: ["gold", "silver"],
});

describe("a Required custom field is required by the dialogs (#2478)", () => {
  it("New Subnet refuses to create until the Required field has a value", async () => {
    answer("ipamApi", "listBlocks", () =>
      Promise.resolve([
        { id: "blk-1", space_id: "sp-1", network: "10.84.0.0/16" },
      ]),
    );
    answer("ipamApi", "listTemplates", () => Promise.resolve([]));
    answer("customFieldsApi", "list", () =>
      Promise.resolve([cf({ name: "owner", label: "Owner" })]),
    );
    answer("ipamApi", "effectiveBlockFields", () =>
      Promise.resolve({ custom_fields: {}, custom_field_sources: {} }),
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
    await findControl("Owner *");
    fireEvent.change(control("Network (CIDR)"), {
      target: { value: "10.84.20.0/24" },
    });
    await press("Create");
    await screen.findByText(/Required custom field need a value: Owner/);
    expect(createSubnet).not.toHaveBeenCalled();

    fireEvent.change(control("Owner *"), { target: { value: "neteng" } });
    await press("Create");
    await waitFor(() => expect(createSubnet).toHaveBeenCalledTimes(1));
    expect(createSubnet.mock.calls[0][0]).toMatchObject({
      custom_fields: { owner: "neteng" },
    });
  });

  it("New Subnet accepts a Required field its block already carries", async () => {
    answer("ipamApi", "listBlocks", () =>
      Promise.resolve([
        { id: "blk-1", space_id: "sp-1", network: "10.84.0.0/16" },
      ]),
    );
    answer("ipamApi", "listTemplates", () => Promise.resolve([]));
    answer("customFieldsApi", "list", () =>
      Promise.resolve([cf({ name: "owner", label: "Owner" })]),
    );
    answer("ipamApi", "effectiveBlockFields", () =>
      Promise.resolve({
        custom_fields: { owner: "from-block" },
        custom_field_sources: { owner: "block:blk-1" },
      }),
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
    await findControl("Owner *");
    fireEvent.change(control("Network (CIDR)"), {
      target: { value: "10.84.20.0/24" },
    });
    await press("Create");
    await waitFor(() => expect(createSubnet).toHaveBeenCalledTimes(1));
  });

  it("New IP Block refuses to create without the Required select's value", async () => {
    answer("ipamApi", "listBlocks", () => Promise.resolve([]));
    answer("ipamApi", "listTemplates", () => Promise.resolve([]));
    answer("customFieldsApi", "list", () => Promise.resolve([TIER]));
    const createBlock = sink({ id: "blk-new" });
    answer("ipamApi", "createBlock", createBlock);
    open(<CreateBlockModal spaceId="sp-1" onClose={() => {}} />);
    const select = await findControl<HTMLSelectElement>("Tier *");
    // No option nobody chose: it shows the empty choice, not "gold".
    expect(select.value).toBe("");
    fireEvent.change(control("Network (CIDR)"), {
      target: { value: "10.85.0.0/16" },
    });
    await press("Create Block");
    await screen.findByText(/Required custom field need a value: Tier/);
    expect(createBlock).not.toHaveBeenCalled();
  });

  it("Edit IP Block shows the empty choice, and an untouched Save is not refused", async () => {
    answer("customFieldsApi", "list", () => Promise.resolve([TIER]));
    answer("ipamApi", "effectiveBlockFields", () =>
      Promise.resolve({ custom_fields: {}, custom_field_sources: {} }),
    );
    const updateBlock = sink({});
    answer("ipamApi", "updateBlock", updateBlock);
    const block = {
      id: "b-1",
      space_id: "sp-1",
      parent_block_id: null,
      network: "10.98.0.0/16",
      name: "top",
      custom_fields: {},
      tags: {},
      utilization_percent: 0,
      allocated_ips: 0,
      total_ips: 65536,
    } as unknown as IPBlock;
    open(<EditBlockModal block={block} onClose={() => {}} />);
    const select = await findControl<HTMLSelectElement>("Tier *");
    expect(select.value).toBe("");
    await press("Save");
    await waitFor(() => expect(updateBlock).toHaveBeenCalledTimes(1));
    expect(
      (updateBlock.mock.calls[0][1] as { custom_fields: unknown })
        .custom_fields,
    ).toEqual({});
  });

  it("Edit IP Block refuses to blank a Required field it holds", async () => {
    answer("customFieldsApi", "list", () => Promise.resolve([TIER]));
    answer("ipamApi", "effectiveBlockFields", () =>
      Promise.resolve({ custom_fields: {}, custom_field_sources: {} }),
    );
    const updateBlock = sink({});
    answer("ipamApi", "updateBlock", updateBlock);
    const block = {
      id: "b-1",
      space_id: "sp-1",
      parent_block_id: null,
      network: "10.98.0.0/16",
      name: "top",
      custom_fields: { tier: "gold" },
      tags: {},
      utilization_percent: 0,
      allocated_ips: 0,
      total_ips: 65536,
    } as unknown as IPBlock;
    open(<EditBlockModal block={block} onClose={() => {}} />);
    const select = await findControl<HTMLSelectElement>("Tier *");
    expect(select.value).toBe("gold");
    fireEvent.change(select, { target: { value: "" } });
    await press("Save");
    await screen.findByText(/Required custom field need a value: Tier/);
    expect(updateBlock).not.toHaveBeenCalled();
  });
});
