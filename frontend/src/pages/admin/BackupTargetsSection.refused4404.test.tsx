/**
 * @vitest-environment jsdom
 *
 * A refused Run now / Test connection / Delete on a destination row is drawn
 * through FormError (role="alert"), so a screen reader hears why the press did
 * nothing, and the line clears when the operator tries again (#4404).
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
import type { BackupTarget } from "@/lib/api";

const list = vi.fn<() => Promise<BackupTarget[]>>();
const test = vi.fn();
const remove = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    formatApiError: actual.formatApiError,
    backupTargetsApi: { list, test, remove },
  };
});
vi.mock("./BackupSectionsPicker", () => ({ BackupSectionsPicker: () => null }));

const { BackupTargetsSection } = await import("./BackupTargetsSection");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const row = (): BackupTarget =>
  ({
    id: "t-1",
    name: "refused-row-1",
    description: "",
    kind: "azure_blob",
    enabled: true,
    config: {},
    passphrase_set: true,
    passphrase_hint: "",
    schedule_cron: null,
    retention_keep_last_n: null,
    retention_keep_days: null,
    last_run_status: "never",
    last_run_at: null,
    last_run_filename: null,
    last_run_node: null,
    last_run_bytes: null,
    last_run_duration_ms: null,
    last_run_error: null,
    next_run_at: null,
    drill_enabled: false,
    drill_cron: null,
    drill_next_run_at: null,
    drill_last_status: "never",
    drill_last_at: null,
    created_at: "2026-10-13T00:00:00Z",
    modified_at: "2026-10-13T00:00:00Z",
  }) as BackupTarget;

const refusal = () =>
  Promise.reject({
    isAxiosError: true,
    response: { status: 404, data: { detail: "backup target not found" } },
  });

function open() {
  list.mockResolvedValue([row()]);
  render(
    <QueryClientProvider
      client={
        new QueryClient({
          defaultOptions: {
            queries: { retry: false },
            mutations: { retry: false },
          },
        })
      }
    >
      <BackupTargetsSection />
    </QueryClientProvider>,
  );
}

describe(
  "a refused destination-row action is announced (#4404)",
  { timeout: 30000 },
  () => {
    it("announces a refused Test connection and clears it on retry", async () => {
      test.mockImplementationOnce(refusal);
      open();
      fireEvent.click(await screen.findByTitle("Test connection"));
      const alert = await screen.findByRole("alert", {}, { timeout: 10000 });
      expect(alert.textContent).toContain("backup target not found");

      test.mockImplementationOnce(() => new Promise(() => {}));
      fireEvent.click(screen.getByTitle("Test connection"));
      await waitFor(() => expect(screen.queryByRole("alert")).toBeNull(), {
        timeout: 10000,
      });
    });

    it("announces a refused Delete", async () => {
      vi.spyOn(window, "confirm").mockReturnValue(true);
      remove.mockImplementationOnce(refusal);
      open();
      fireEvent.click(await screen.findByTitle("Delete"));
      const alert = await screen.findByRole("alert", {}, { timeout: 10000 });
      expect(alert.textContent).toContain("backup target not found");
    });
  },
);
