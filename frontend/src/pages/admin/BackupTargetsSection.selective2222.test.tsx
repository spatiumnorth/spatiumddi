/**
 * @vitest-environment jsdom
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
const listSections = vi.fn(() => Promise.resolve([]));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    formatApiError: actual.formatApiError,
    backupTargetsApi: {
      list,
      listArchives,
      previewArchiveManifest,
      restoreFromArchive: vi.fn(),
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

function selectiveRadio(): HTMLInputElement {
  return screen
    .getByText("Selective restore", { selector: "strong" })
    .closest("label")!
    .querySelector("input") as HTMLInputElement;
}

describe("Restore from archive: Selective needs a custom-format dump (#2222)", () => {
  it("disables Selective with the reason for a plain-SQL archive", async () => {
    await openModal(preview("plain"));
    expect(await screen.findByText(/dump is plain SQL/)).toBeTruthy();
    expect(selectiveRadio().disabled).toBe(true);
    expect(previewArchiveManifest).toHaveBeenCalledWith("t-1", NAME);
  });

  it("allows Selective for a custom-format archive", async () => {
    await openModal(preview("custom"));
    await vi.waitFor(() => expect(selectiveRadio().disabled).toBe(false));
    expect(screen.queryByText(/dump is plain SQL/)).toBeNull();
  });

  it("keeps Full restore available when the format cannot be read", async () => {
    await openModal(new Error("destination unreachable"));
    expect(await screen.findByText(/could not be read/)).toBeTruthy();
    expect(selectiveRadio().disabled).toBe(true);
    const full = screen
      .getByText("Full restore", { selector: "strong" })
      .closest("label")!
      .querySelector("input") as HTMLInputElement;
    expect(full.disabled).toBe(false);
    expect(full.checked).toBe(true);
  });
});
