/**
 * @vitest-environment jsdom
 *
 * #3546: a block's allocation band disables its free segments for a caller
 * who may not create a subnet. While the permissions read is loading or has
 * failed, that is not a missing grant, so the tooltip says so instead of
 * "Requires write permission on subnets" (which a superadmin saw).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, waitFor } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { queryClient as appQueryClient } from "@/lib/queryClient";
import {
  PERMISSIONS_CHECKING,
  PERMISSIONS_UNREADABLE,
} from "@/hooks/usePermissions";
import type { IPBlock, IPSpace } from "@/lib/api";

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
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: () => true,
  }),
}));

const { BlockDetailView } = await import("./IPAMPage");

appQueryClient.setQueryDefaults(["my-permissions"], { retry: false });

afterEach(() => {
  cleanup();
  appQueryClient.clear();
  for (const name of Object.keys(answers)) delete answers[name];
});

const block = {
  id: "blk-1",
  space_id: "sp-1",
  parent_block_id: null,
  network: "10.142.0.0/16",
  name: "",
  created_at: "2026-11-03T00:00:00Z",
  utilization_percent: 0,
  total_ips: 0,
  allocated_ips: 0,
  tags: {},
  custom_fields: {},
  customer_id: null,
  site_id: null,
} as unknown as IPBlock;
const space = { id: "sp-1", name: "lab" } as unknown as IPSpace;

async function openBlock(myPermissions: () => Promise<unknown>) {
  answers.authApi = { myPermissions };
  answers.ipamApi = {
    listBlocks: () => Promise.resolve([block]),
    listTemplates: () => Promise.resolve([]),
    blockFreeSpace: () =>
      Promise.resolve([
        {
          network: "10.142.0.0/24",
          first: "10.142.0.0",
          last: "10.142.0.255",
          size: 256,
          prefix_len: 24,
        },
      ]),
  };
  answers.customFieldsApi = { list: () => Promise.resolve([]) };
  render(
    <QueryClientProvider client={appQueryClient}>
      <MemoryRouter>
        <BlockDetailView
          block={block}
          spaceName="lab"
          ancestors={[]}
          allBlocks={[block]}
          allSubnets={[]}
          space={space}
          onSelectSpace={() => {}}
          onSelectBlock={() => {}}
          onSelectSubnet={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 80));
  });
}

const band = () =>
  document.querySelector(
    'button[aria-label^="Free 10.142.0.0/24"]',
  ) as HTMLButtonElement | null;

describe("the allocation band's free segments with unread permissions (#3546)", () => {
  it("say the permissions could not be read when the read failed", async () => {
    await openBlock(() => Promise.reject(new Error("Network Error")));
    await waitFor(() => expect(band()).toBeTruthy());
    await waitFor(() => expect(band()!.title).toBe(PERMISSIONS_UNREADABLE));
    expect(band()!.disabled).toBe(true);
  });

  it("say the permissions are being checked while the read is loading", async () => {
    await openBlock(() => new Promise(() => {}));
    await waitFor(() => expect(band()).toBeTruthy());
    expect(band()!.title).toBe(PERMISSIONS_CHECKING);
    expect(band()!.disabled).toBe(true);
  });

  it("keep the role wording when the grants are read and write is missing", async () => {
    await openBlock(() =>
      Promise.resolve({
        is_superadmin: false,
        grants: [{ action: "read", resource_type: "*", resource_id: null }],
      }),
    );
    await waitFor(() => expect(band()).toBeTruthy());
    await waitFor(() =>
      expect(band()!.title).toBe("Requires write permission on subnets"),
    );
  });
});
