/**
 * @vitest-environment jsdom
 *
 * A block's Find Free files "Create subnet here" under the block the row
 * names, not the block whose Tools opened the dialog (#2417).
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
import type { IPBlock, IPSpace } from "@/lib/api";

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

const { BlockDetailView } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

const STAMP = "2026-10-02T00:00:00Z";
const space = { id: "sp-1", name: "lab" } as unknown as IPSpace;
const outer = {
  id: "blk-outer",
  space_id: "sp-1",
  network: "10.222.0.0/20",
  name: "outer",
  created_at: STAMP,
  utilization_percent: 0,
  total_ips: 0,
  allocated_ips: 0,
  tags: {},
  custom_fields: {},
} as unknown as IPBlock;
const child = {
  id: "blk-child",
  space_id: "sp-1",
  parent_block_id: "blk-outer",
  network: "10.222.8.0/21",
  name: "child",
  created_at: STAMP,
  utilization_percent: 0,
  total_ips: 0,
  allocated_ips: 0,
  tags: {},
  custom_fields: {},
} as unknown as IPBlock;

describe("Create subnet here from a block's Find Free (#2417)", () => {
  it("sends the block the row names", async () => {
    answer("ipamApi", "listBlocks", () => Promise.resolve([outer, child]));
    answer("ipamApi", "listTemplates", () => Promise.resolve([]));
    answer("customFieldsApi", "list", () => Promise.resolve([]));
    answer("ipamApi", "findFreeSpace", () =>
      Promise.resolve({
        candidates: [
          {
            cidr: "10.222.8.0/24",
            parent_block_id: "blk-child",
            parent_block_cidr: "10.222.8.0/21",
            free_addresses: 254,
          },
        ],
        summary: {},
      }),
    );
    const createSubnet = vi.fn((..._a: unknown[]) =>
      Promise.resolve({ id: "sub-new" }),
    );
    answer("ipamApi", "createSubnet", createSubnet);

    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <BlockDetailView
            block={outer}
            spaceName="lab"
            ancestors={[]}
            allBlocks={[outer, child]}
            allSubnets={[]}
            space={space}
            onSelectSpace={() => {}}
            onSelectBlock={() => {}}
            onSelectSubnet={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    fireEvent.click(await screen.findByRole("button", { name: /Tools/ }));
    fireEvent.click(await screen.findByText("Find Free…"));
    fireEvent.click(await screen.findByRole("button", { name: "Find" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Create subnet here" }),
    );

    const create = (await screen.findByRole("button", {
      name: "Create",
    })) as HTMLButtonElement;
    await waitFor(() => expect(create.disabled).toBe(false));
    fireEvent.click(create);

    await waitFor(() => expect(createSubnet).toHaveBeenCalledTimes(1));
    expect(createSubnet.mock.calls[0][0]).toMatchObject({
      network: "10.222.8.0/24",
      block_id: "blk-child",
    });
  });
});
