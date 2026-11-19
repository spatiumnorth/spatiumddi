/**
 * @vitest-environment jsdom
 *
 * A Bulk allocate refreshes the block list too (#3325): the server recounts
 * the block chain in the same request, so the parent's table must refetch
 * rather than keep drawing the old Used figure.
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
import type { Subnet } from "@/lib/api";

vi.mock("@/lib/api", () => ({
  formatApiError: (e: unknown) => String(e),
  ipamApi: {
    getEffectiveSubnetDns: () => Promise.resolve({ dns_group_ids: [] }),
    bulkAllocatePreview: () =>
      Promise.resolve({
        total: 2,
        will_create: 2,
        conflicts_in_use: 0,
        conflicts_in_pool: 0,
        conflicts_fqdn: 0,
        sample: [],
        warnings: [],
      }),
    bulkAllocateCommit: () =>
      Promise.resolve({
        created: 2,
        skipped_in_use: 0,
        skipped_in_pool: 0,
        skipped_fqdn_collision: 0,
        sample_created: [],
        summary: [],
      }),
  },
  dnsApi: { listZones: () => Promise.resolve([]) },
}));
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

const { BulkAllocateModal } = await import("./BulkAllocateModal");

afterEach(cleanup);

describe("Bulk allocate commit (#3325)", () => {
  it("invalidates the block list", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const spy = vi.spyOn(qc, "invalidateQueries");
    render(
      <QueryClientProvider client={qc}>
        <BulkAllocateModal
          subnet={{ id: "s", network: "10.98.9.0/24", name: "x" } as Subnet}
          onClose={() => {}}
        />
      </QueryClientProvider>,
    );
    const tpl = await screen.findByPlaceholderText(/dhcp-\{n\}/);
    fireEvent.change(tpl, { target: { value: "h-{n}" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    fireEvent.click(await screen.findByRole("button", { name: /^Allocate 2/ }));
    await waitFor(() =>
      expect(spy.mock.calls.map((c) => c[0]?.queryKey)).toContainEqual([
        "blocks",
      ]),
    );
  });
});
