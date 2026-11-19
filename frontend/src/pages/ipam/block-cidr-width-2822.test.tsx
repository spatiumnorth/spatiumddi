/**
 * @vitest-environment jsdom
 *
 * IPAM tree: a block row keeps its CIDR at full width and cuts the name (#2822).
 *
 * jsdom does no layout, so this holds the classes that decide it: the CIDR
 * may neither shrink nor wrap, and the name is the one that truncates.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import { DndContext } from "@dnd-kit/core";
import type { IPBlock } from "@/lib/api";

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

const { BlockTreeRow } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DndContext>{ui}</DndContext>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const block = {
  id: "b-1",
  space_id: "sp-1",
  network: "10.20.0.0/16",
  name: "branch-portland-with-a-very-long-name",
  customer_id: null,
  site_id: null,
} as unknown as IPBlock;

describe("BlockTreeRow CIDR width (#2822)", () => {
  it("never shrinks the CIDR and truncates the name instead", () => {
    open(
      <BlockTreeRow
        node={{ block, children: [], subnets: [] }}
        selectedSubnetId={null}
        selectedBlockId={null}
        onSelectBlock={() => {}}
        onSelectSubnet={() => {}}
        onDeleteSubnet={() => {}}
        onCreateSubnet={() => {}}
        onCreateChildBlock={() => {}}
        depth={0}
      />,
    );
    const cidr = screen.getByText("10.20.0.0/16");
    expect(cidr.className).toContain("shrink-0");
    expect(cidr.className).toContain("whitespace-nowrap");
    expect(cidr.className).not.toMatch(/\bflex-1\b|\btruncate\b/);
    const name = screen.getByText(block.name as string);
    expect(name.className).toContain("min-w-0");
    expect(name.className).toContain("truncate");
  });
});
