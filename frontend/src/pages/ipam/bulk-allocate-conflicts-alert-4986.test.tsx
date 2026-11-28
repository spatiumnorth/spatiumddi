/**
 * @vitest-environment jsdom
 *
 * Bulk allocate's preview counts addresses outside the caller's address sets
 * as conflicts, as the commit does: with on_collision="abort" the commit
 * refuses them, so Allocate must not be offered.
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
        total: 10,
        will_create: 5,
        conflicts_in_use: 0,
        conflicts_in_pool: 0,
        conflicts_fqdn: 0,
        conflicts_no_perm: 5,
        sample: [],
        warnings: [],
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

describe("Bulk allocate conflicts box (#4986)", () => {
  async function previewWith(mode: "abort" | "skip") {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <BulkAllocateModal
          subnet={{ id: "s", network: "10.0.5.0/24", name: "x" } as Subnet}
          onClose={() => {}}
        />
      </QueryClientProvider>,
    );
    const template = screen.getByText("Hostname template", {
      selector: "label",
    }).nextElementSibling as HTMLInputElement;
    fireEvent.change(template, { target: { value: "h-{n}" } });
    const sel = screen.getByText("On collision", { selector: "label" })
      .nextElementSibling as HTMLSelectElement;
    fireEvent.change(sel, { target: { value: mode } });
    await waitFor(() =>
      expect(
        (screen.getByRole("button", { name: /Preview/ }) as HTMLButtonElement)
          .disabled,
      ).toBe(false),
    );
    fireEvent.click(screen.getByRole("button", { name: /Preview/ }));
    await screen.findByText("5 conflicts");
  }

  it("is an alert when it blocks the commit", async () => {
    await previewWith("abort");
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("5 conflicts");
    expect(alert.textContent).toContain("back out and switch to");
  });

  it("is not an alert when conflicts are skipped", async () => {
    await previewWith("skip");
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
