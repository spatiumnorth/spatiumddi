/**
 * @vitest-environment jsdom
 *
 * A destination's Restore-from-archive modal keeps Apply disabled for an
 * archive the restore itself would refuse, and says why (#3287).
 *
 * The modal read the archive's manifest preview only to decide whether to
 * offer Selective, so an archive the preview called not restorable (here,
 * one taken on a schema this install cannot place) still offered a Full
 * restore that the API then refused after the passphrase and the phrase
 * were typed.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
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

const { BackupTargetsSection } = await import("./BackupTargetsSection");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const NAME = "spatiumddi-backup-x-20261031-120000-a1a455.zip";
const REFUSAL =
  "This archive was taken on a NEWER schema than this install: its head " +
  "'ffffffffffff' is not an ancestor of 'abc123'. Upgrade SpatiumDDI on " +
  "this install first, then re-run the restore.";

function preview(refusal: string | null): BackupManifestPreviewResponse {
  return {
    manifest: {
      format: "spatiumddi-backup",
      format_version: 2,
      dump_format: "custom",
      schema_version: refusal ? "ffffffffffff" : undefined,
    },
    archive_bytes: 10,
    format_recognised: true,
    dump_format: "custom",
    selective_restore_supported: true,
    restorable: refusal === null,
    restore_refusal: refusal,
  };
}

async function openAndFill(p: BackupManifestPreviewResponse) {
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
        created_at: "2026-10-31T12:00:00Z",
        node_name: null,
      },
    ],
    note: null,
  });
  previewArchiveManifest.mockResolvedValue(p);
  render(
    (
      <QueryClientProvider client={new QueryClient()}>
        <BackupTargetsSection />
      </QueryClientProvider>
    ) as ReactElement,
  );
  fireEvent.click(await screen.findByTitle("Expand archives"));
  fireEvent.click(await screen.findByTitle("Restore from this archive"));
  await vi.waitFor(() =>
    expect(previewArchiveManifest).toHaveBeenCalledWith("t-1", NAME),
  );
  const dialog = await screen.findByRole("dialog");
  fireEvent.change(dialog.querySelector('input[type="password"]')!, {
    target: { value: "correct-horse-battery" },
  });
  fireEvent.change(
    dialog.querySelector('input[placeholder="RESTORE-FROM-BACKUP"]')!,
    {
      target: { value: "RESTORE-FROM-BACKUP" },
    },
  );
}

function applyButton(): HTMLButtonElement {
  return screen.getByRole("button", {
    name: "Apply restore",
  }) as HTMLButtonElement;
}

describe("Restore from archive: an archive the restore refuses (#3287)", () => {
  it("disables Apply for a Full restore and shows the refusal", async () => {
    await openAndFill(preview(REFUSAL));
    expect(
      await screen.findByText(/NEWER schema than this install/),
    ).toBeTruthy();
    expect(screen.getByText(/This archive cannot be restored/)).toBeTruthy();
    await vi.waitFor(() => expect(applyButton().disabled).toBe(true));
    fireEvent.click(applyButton());
    expect(restoreFromArchive).not.toHaveBeenCalled();
  });

  it("enables Apply for a Full restore of a restorable archive", async () => {
    await openAndFill(preview(null));
    await vi.waitFor(() => expect(applyButton().disabled).toBe(false));
    expect(screen.queryByText(/This archive cannot be restored/)).toBeNull();
  });
});
