/**
 * @vitest-environment jsdom
 *
 * A restore from a destination also ends the session, so it leaves the
 * sign-in notice, and clears it when the restore was refused (#4676).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type {
  BackupArchiveList,
  BackupManifestPreviewResponse,
  BackupTarget,
} from "@/lib/api";

const list = vi.fn<() => Promise<BackupTarget[]>>();
const listArchives = vi.fn<() => Promise<BackupArchiveList>>();
const previewArchiveManifest =
  vi.fn<(id: string, f: string) => Promise<BackupManifestPreviewResponse>>();
const restoreFromArchive = vi.fn();
const listSections = vi.fn(() => Promise.resolve([]));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    formatApiError: actual.formatApiError,
    backupTargetsApi: {
      list,
      listArchives,
      previewArchiveManifest,
      restoreFromArchive,
    },
    backupApi: { listSections },
  };
});

import { RESTORE_IN_FLIGHT_KEY } from "@/lib/restoreInFlight";

const { BackupTargetsSection } = await import("./BackupTargetsSection");

beforeEach(() => sessionStorage.clear());
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const NAME = "spatiumddi-backup-x-20261013-065126-a1a455.zip";

function preview(
  dump_format: "plain" | "custom",
): BackupManifestPreviewResponse {
  return {
    manifest: { format: "spatiumddi-backup", format_version: 2, dump_format },
    archive_bytes: 10,
    format_recognised: true,
    dump_format,
    selective_restore_supported: dump_format === "custom",
  };
}

async function openModal(p: BackupManifestPreviewResponse | Error) {
  list.mockResolvedValue([
    {
      id: "t-1",
      name: "local",
      kind: "local_volume",
      enabled: true,
      config: {},
      write_only: false,
      last_run_status: "never",
    } as unknown as BackupTarget,
  ]);
  listArchives.mockResolvedValue({
    archives: [
      {
        filename: NAME,
        size_bytes: 10,
        created_at: "2026-10-13T06:51:26Z",
        node_name: null,
      },
    ],
    note: null,
  });
  if (p instanceof Error) previewArchiveManifest.mockRejectedValue(p);
  else previewArchiveManifest.mockResolvedValue(p);
  render(
    (
      <QueryClientProvider client={new QueryClient()}>
        <BackupTargetsSection />
      </QueryClientProvider>
    ) as ReactElement,
  );
  fireEvent.click(await screen.findByTitle("Expand archives"));
  fireEvent.click(await screen.findByTitle("Restore from this archive"));
}

async function fillAndApply() {
  fireEvent.change(await screen.findByLabelText(/Passphrase/), {
    target: { value: "passphrase1" },
  });
  fireEvent.change(screen.getByPlaceholderText("RESTORE-FROM-BACKUP"), {
    target: { value: "RESTORE-FROM-BACKUP" },
  });
  fireEvent.click(screen.getByText("Apply restore"));
}

describe("destination restore sign-in note (#4676)", () => {
  it("is set when the restore succeeds, since the session ends", async () => {
    await openModal(preview("custom"));
    restoreFromArchive.mockResolvedValue({
      success: true,
      filename: NAME,
      duration_ms: 5,
      warnings: ["note"],
    });
    await fillAndApply();
    await screen.findByText("Close");
    expect(sessionStorage.getItem(RESTORE_IN_FLIGHT_KEY)).not.toBeNull();
  });

  it("is cleared when the restore is refused", async () => {
    await openModal(preview("custom"));
    restoreFromArchive.mockRejectedValue({
      response: { status: 422, data: { detail: "refused" } },
    });
    await fillAndApply();
    await vi.waitFor(() => expect(restoreFromArchive).toHaveBeenCalled());
    await vi.waitFor(() =>
      expect(sessionStorage.getItem(RESTORE_IN_FLIGHT_KEY)).toBeNull(),
    );
  });
});
