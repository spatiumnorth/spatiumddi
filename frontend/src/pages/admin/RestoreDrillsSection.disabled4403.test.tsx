/**
 * @vitest-environment jsdom
 *
 * A disabled destination's drill cron is not a live schedule: the drill sweep
 * only fires for enabled destinations, so the row says it is paused (#4403).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { BackupTarget } from "@/lib/api";

const list = vi.fn<() => Promise<BackupTarget[]>>();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    formatApiError: actual.formatApiError,
    backupTargetsApi: {
      list,
      update: vi.fn(),
      drillReadiness: vi.fn().mockResolvedValue({
        targets: [],
        total_targets: 0,
        verified_targets: 0,
        unverified_targets: 0,
      }),
      listDrills: vi.fn().mockResolvedValue([]),
      runDrill: vi.fn(),
    },
  };
});

const { RestoreDrillsSection } = await import("./RestoreDrillsSection");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const row = (over: Partial<BackupTarget>): BackupTarget =>
  ({
    id: "t1",
    name: "dest-1",
    kind: "azure_blob",
    enabled: true,
    drill_enabled: true,
    drill_cron: "0 4 1 1 *",
    drill_last_status: "never",
    ...over,
  }) as BackupTarget;

function open() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <RestoreDrillsSection />
    </QueryClientProvider>,
  );
}

describe(
  "Restore Drills schedule of a disabled destination (#4403)",
  { timeout: 30000 },
  () => {
    it("says a disabled destination's drills do not run", async () => {
      list.mockResolvedValue([row({ enabled: false })]);
      open();
      await screen.findByText("0 4 1 1 *", {}, { timeout: 10000 });
      expect(screen.getByText(/paused: destination disabled/)).toBeTruthy();
    });

    it("says nothing extra for an enabled destination", async () => {
      list.mockResolvedValue([row({})]);
      open();
      await screen.findByText("0 4 1 1 *", {}, { timeout: 10000 });
      expect(screen.queryByText(/paused/)).toBeNull();
    });
  },
);
