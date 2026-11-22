/**
 * @vitest-environment jsdom
 *
 * The sign-in notice follows what the restore actually did (#4676). A 401 on
 * the restore POST means the session ended BEFORE Apply and nothing was
 * restored, so no "Restore applied" notice may be left behind. A dropped
 * connection (no response) is the restore's own session loss and keeps it.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RESTORE_IN_FLIGHT_KEY } from "@/lib/restoreInFlight";

const previewManifest = vi.fn();
const restore = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ is_superadmin: true }) },
    backupApi: {
      ...actual.backupApi,
      previewManifest,
      restore,
      lastRestore: () => Promise.resolve(null),
    },
  };
});
vi.mock("./BackupSectionsPicker", () => ({ BackupSectionsPicker: () => null }));
vi.mock("./BackupTargetsSection", () => ({ BackupTargetsSection: () => null }));
vi.mock("./FactoryResetSection", () => ({ FactoryResetSection: () => null }));
vi.mock("./RestoreDrillsSection", () => ({
  RestoreDrillsSection: () => null,
}));

const { BackupPage } = await import("./BackupPage");

beforeEach(() => sessionStorage.clear());
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

async function apply() {
  previewManifest.mockResolvedValue({
    manifest: { format: "spatiumddi-backup", format_version: 2 },
    archive_bytes: 1,
    format_recognised: true,
    dump_format: "custom",
    selective_restore_supported: true,
  });
  const { container } = render(
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
      <BackupPage />
    </QueryClientProvider>,
  );
  fireEvent.change(container.querySelector('input[type="file"]')!, {
    target: {
      files: [new File(["zip"], "a.zip", { type: "application/zip" })],
    },
  });
  fireEvent.change(
    await screen.findByPlaceholderText("The passphrase used at backup time"),
    { target: { value: "passphrase-123" } },
  );
  fireEvent.change(screen.getByPlaceholderText("RESTORE-FROM-BACKUP"), {
    target: { value: "RESTORE-FROM-BACKUP" },
  });
  fireEvent.click(screen.getByText("Apply restore"));
}

describe("restore sign-in note (#4676)", () => {
  it("is set while the restore is in flight", async () => {
    restore.mockReturnValue(new Promise(() => {}));
    await apply();
    await vi.waitFor(() =>
      expect(sessionStorage.getItem(RESTORE_IN_FLIGHT_KEY)).not.toBeNull(),
    );
  });

  it("is cleared when the restore POST answers 401", async () => {
    restore.mockRejectedValue({ response: { status: 401 } });
    await apply();
    await vi.waitFor(() => expect(restore).toHaveBeenCalled());
    await vi.waitFor(() =>
      expect(sessionStorage.getItem(RESTORE_IN_FLIGHT_KEY)).toBeNull(),
    );
  });

  it("is kept when the connection drops with no response", async () => {
    restore.mockRejectedValue(new Error("Network Error"));
    await apply();
    await vi.waitFor(() => expect(restore).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 20));
    expect(sessionStorage.getItem(RESTORE_IN_FLIGHT_KEY)).not.toBeNull();
  });
});
