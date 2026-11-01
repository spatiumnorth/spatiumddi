/**
 * @vitest-environment jsdom
 *
 * IPAM tree opens only to Settings' Default Expanded Depth (#3290).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { DndContext } from "@dnd-kit/core";
import type { IPBlock, Subnet } from "@/lib/api";

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

const { BlockTreeRow } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const mk = (id: string, network: string) =>
  ({
    id,
    space_id: "sp",
    network,
    name: "",
    customer_id: null,
    site_id: null,
  }) as unknown as IPBlock;

// /16 > /20 > /24 > /26 (levels 1..4)
const leaf = {
  block: mk("4", "10.249.17.64/26"),
  children: [],
  subnets: [] as Subnet[],
};
const l3 = {
  block: mk("3", "10.249.17.0/24"),
  children: [leaf],
  subnets: [] as Subnet[],
};
const l2 = {
  block: mk("2", "10.249.16.0/20"),
  children: [l3],
  subnets: [] as Subnet[],
};
const l1 = {
  block: mk("1", "10.249.0.0/16"),
  children: [l2],
  subnets: [] as Subnet[],
};

function open() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DndContext>
          <BlockTreeRow
            node={l1}
            selectedSubnetId={null}
            selectedBlockId={null}
            onSelectBlock={() => {}}
            onSelectSubnet={() => {}}
            onDeleteSubnet={() => {}}
            onCreateSubnet={() => {}}
            onCreateChildBlock={() => {}}
            depth={0}
          />
        </DndContext>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const state = (cidr: string) =>
  screen.getByRole("treeitem", { name: cidr }).getAttribute("aria-expanded");

describe("IPAM tree default expanded depth (#3290)", () => {
  it("collapses blocks past the stored depth", async () => {
    answers.settingsApi = {
      get: () => Promise.resolve({ subnet_tree_default_expanded_depth: 2 }),
    };
    open();
    await waitFor(() => expect(state("10.249.17.0/24")).toBe("false"));
    expect(state("10.249.0.0/16")).toBe("true");
    expect(state("10.249.16.0/20")).toBe("true");
  });

  it("depth 0 starts everything collapsed", async () => {
    answers.settingsApi = {
      get: () => Promise.resolve({ subnet_tree_default_expanded_depth: 0 }),
    };
    open();
    await waitFor(() => expect(state("10.249.0.0/16")).toBe("false"));
  });

  it("a deeper setting opens deeper", async () => {
    answers.settingsApi = {
      get: () => Promise.resolve({ subnet_tree_default_expanded_depth: 4 }),
    };
    open();
    await waitFor(() => expect(state("10.249.17.0/24")).toBe("true"));
  });
});
