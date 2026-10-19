/**
 * @vitest-environment jsdom
 *
 * The Manual restore card refuses a selective restore of a plain-SQL
 * archive before anything is sent (#2201).
 *
 * The API refuses one whenever the archive's dump is not pg_dump's custom
 * format. The card used to decide from `format_version === 2`, and every
 * archive is version 2 — an Exclude-secrets archive too, whose dump is
 * plain SQL. So the card offered Apply for a restore the API always
 * refuses. It now reads the dump format the server resolved with the
 * restore's own helper, so the two answer alike.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { BackupManifestPreviewResponse } from "@/lib/api";

const previewManifest =
  vi.fn<(f: File) => Promise<BackupManifestPreviewResponse>>();
const restore = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    backupApi: { ...actual.backupApi, previewManifest, restore },
  };
});
// The section picker's own catalog query is not under test: a stub that
// switches to Selective with one section ticked.
vi.mock("./BackupSectionsPicker", () => ({
  BackupSectionsPicker: ({
    onModeChange,
    onChange,
  }: {
    onModeChange: (m: "full" | "selective") => void;
    onChange: (s: string[]) => void;
  }) => (
    <div>
      <button type="button" onClick={() => onModeChange("full")}>
        stub-full
      </button>
      <button
        type="button"
        onClick={() => {
          onModeChange("selective");
          onChange(["ipam"]);
        }}
      >
        stub-selective
      </button>
    </div>
  ),
}));
vi.mock("./BackupTargetsSection", () => ({ BackupTargetsSection: () => null }));
vi.mock("./FactoryResetSection", () => ({ FactoryResetSection: () => null }));
vi.mock("./RestoreDrillsSection", () => ({
  RestoreDrillsSection: () => null,
}));

const { BackupPage } = await import("./BackupPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const NOTICE = /Selective restore needs an archive whose database dump/;

async function pickAndFill(preview: BackupManifestPreviewResponse) {
  previewManifest.mockResolvedValue(preview);
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
  const file = new File(["zip"], "a.zip", { type: "application/zip" });
  fireEvent.change(container.querySelector('input[type="file"]')!, {
    target: { files: [file] },
  });
  await screen.findByText("stub-selective");
  fireEvent.change(
    screen.getByPlaceholderText("The passphrase used at backup time"),
    { target: { value: "passphrase-123" } },
  );
  fireEvent.change(screen.getByPlaceholderText("RESTORE-FROM-BACKUP"), {
    target: { value: "RESTORE-FROM-BACKUP" },
  });
  return container;
}

function applyButton(): HTMLButtonElement {
  return screen.getByText("Apply restore").closest("button")!;
}

// What the server answers for an Exclude-secrets archive: version 2, plain.
const EXCLUDE_SECRETS: BackupManifestPreviewResponse = {
  manifest: {
    format: "spatiumddi-backup",
    format_version: 2,
    dump_format: "plain",
  },
  archive_bytes: 100,
  format_recognised: true,
  dump_format: "plain",
  selective_restore_supported: false,
};
const REGULAR: BackupManifestPreviewResponse = {
  manifest: {
    format: "spatiumddi-backup",
    format_version: 2,
    dump_format: "custom",
  },
  archive_bytes: 100,
  format_recognised: true,
  dump_format: "custom",
  selective_restore_supported: true,
};

describe("restore card gates selective restore on the dump format (#2201)", () => {
  it("blocks a selective restore of an Exclude-secrets (plain) archive and says why", async () => {
    await pickAndFill(EXCLUDE_SECRETS);
    fireEvent.click(screen.getByText("stub-selective"));
    expect(screen.getByText(NOTICE)).toBeTruthy();
    expect(screen.getByText(/dump is plain SQL/)).toBeTruthy();
    expect(applyButton().disabled).toBe(true);
    fireEvent.submit(applyButton().closest("form")!);
    expect(restore).not.toHaveBeenCalled();
  });

  it("still offers a full restore of the same archive", async () => {
    await pickAndFill(EXCLUDE_SECRETS);
    fireEvent.click(screen.getByText("stub-full"));
    expect(screen.queryByText(NOTICE)).toBeNull();
    expect(applyButton().disabled).toBe(false);
  });

  it("offers a selective restore of a custom-format archive", async () => {
    await pickAndFill(REGULAR);
    fireEvent.click(screen.getByText("stub-selective"));
    expect(screen.queryByText(NOTICE)).toBeNull();
    expect(applyButton().disabled).toBe(false);
  });

  it("reads the manifest's dump_format when the preview carries no resolved one", async () => {
    await pickAndFill({
      manifest: EXCLUDE_SECRETS.manifest,
      archive_bytes: 100,
      format_recognised: true,
    });
    fireEvent.click(screen.getByText("stub-selective"));
    expect(screen.getByText(NOTICE)).toBeTruthy();
    expect(applyButton().disabled).toBe(true);
  });
});
