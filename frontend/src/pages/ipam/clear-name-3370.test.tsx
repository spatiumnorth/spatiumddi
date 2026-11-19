/**
 * @vitest-environment jsdom
 *
 * #3370 — a cleared Name in Edit Subnet / Edit Block is sent as "" (the API keeps it),
 * never dropped as undefined while the Save reports success.
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

const { EditSubnetModal, EditBlockModal } = await import("./IPAMPage");

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

async function press(name: string) {
  const button = screen.getByRole("button", { name }) as HTMLButtonElement;
  await waitFor(() => expect(button.disabled).toBe(false));
  fireEvent.click(button);
}

const subnet = {
  id: "sub-1",
  space_id: "sp-1",
  block_id: "blk-1",
  network: "10.1.0.0/24",
  name: "named",
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
} as unknown as Subnet;

describe("a cleared Name is sent cleared (#3370)", () => {
  it('Edit Subnet sends name: ""', async () => {
    const updateSubnet = sink(subnet);
    answer("ipamApi", "updateSubnet", updateSubnet);
    answer("ipamApi", "getSubnet", () => Promise.resolve(subnet));
    open(<EditSubnetModal subnet={subnet} onClose={() => {}} />);
    fireEvent.change(await screen.findByDisplayValue("named"), {
      target: { value: "" },
    });
    await press("Save");
    await waitFor(() => expect(updateSubnet).toHaveBeenCalledTimes(1));
    expect(updateSubnet.mock.calls[0][1]).toEqual({ name: "" });
  });

  it('Edit Block sends name: ""', async () => {
    const block = {
      id: "b-1",
      space_id: "sp-1",
      parent_block_id: null,
      network: "10.98.0.0/16",
      name: "core",
      description: "",
      tags: {},
      custom_fields: {},
    };
    const updateBlock = sink(block);
    answer("ipamApi", "updateBlock", updateBlock);
    answer("ipamApi", "getBlock", () => Promise.resolve(block));
    open(<EditBlockModal block={block as never} onClose={() => {}} />);
    fireEvent.change(await screen.findByDisplayValue("core"), {
      target: { value: "" },
    });
    await press("Save");
    await waitFor(() => expect(updateBlock).toHaveBeenCalledTimes(1));
    expect(updateBlock.mock.calls[0][1]).toEqual({ name: "" });
  });
});
