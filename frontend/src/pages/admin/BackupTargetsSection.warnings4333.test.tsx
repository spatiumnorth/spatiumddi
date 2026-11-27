/**
 * @vitest-environment jsdom
 *
 * A destination restore shows the post-restore warnings and stays open (#4333).
 *
 * A destination's Restore-from-archive modal knows an archive's dump
 * format before it offers Selective restore (#2222).
 *
 * The API refuses a selective restore of a plain-SQL archive, and the
 * modal used to offer one for every archive — so an archive copied into a
 * destination by hand was refused only after Apply. The modal now reads
 * the archive's manifest preview for the one archive picked and disables
 * Selective with the reason until that says custom.
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

describe("destination restore post-restore warnings (#4333)", () => {
  it("shows the also-restored warning and stays open until Close", async () => {
    await openModal(preview("custom"));
    restoreFromArchive.mockResolvedValue({
      success: true,
      filename: NAME,
      duration_ms: 5,
      warnings: [
        "Selective restore also restored 9 table(s) outside the sections you selected: ip_address",
      ],
    });
    fireEvent.change(await screen.findByLabelText(/Passphrase/), {
      target: { value: "passphrase1" },
    });
    fireEvent.change(screen.getByPlaceholderText("RESTORE-FROM-BACKUP"), {
      target: { value: "RESTORE-FROM-BACKUP" },
    });
    fireEvent.click(screen.getByText("Apply restore"));
    expect(await screen.findByText(/also restored 9 table/)).toBeTruthy();
    expect(screen.getByText("Close")).toBeTruthy();
  });
});
