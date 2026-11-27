/**
 * @vitest-environment jsdom
 *
 * The restore card's Selective restore refusal for a plain-SQL archive, and
 * the Build + download / Apply restore refusals, are announced (role="alert")
 * (#4965).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const previewManifest = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    backupApi: { ...actual.backupApi, previewManifest },
    backupTargetsApi: { list: vi.fn().mockResolvedValue([]), test: vi.fn() },
  };
});
vi.mock("./BackupSectionsPicker", () => ({
  BackupSectionsPicker: ({
    onModeChange,
  }: {
    onModeChange: (m: "full" | "selective") => void;
  }) => (
    <button onClick={() => onModeChange("selective")}>choose selective</button>
  ),
}));
vi.mock("./FactoryResetSection", () => ({ FactoryResetSection: () => null }));
vi.mock("./RestoreDrillsSection", () => ({
  RestoreDrillsSection: () => null,
}));

const { BackupPage } = await import("./BackupPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("a plain-SQL archive's selective refusal is announced (#4965)", () => {
  it("announces the Selective restore refusal", async () => {
    previewManifest.mockResolvedValueOnce({
      manifest: { format: "spatiumddi-backup", format_version: 2 },
      archive_bytes: 100,
      format_recognised: true,
      restorable: true,
      restore_refusal: null,
      dump_format: "plain",
      selective_restore_supported: false,
    });
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <BackupPage />
      </QueryClientProvider>,
    );
    fireEvent.change(container.querySelector('input[type="file"]')!, {
      target: {
        files: [new File(["zip"], "a.zip", { type: "application/zip" })],
      },
    });
    fireEvent.click(await screen.findByText("choose selective"));
    const alert = await screen.findByRole("alert", {}, { timeout: 10000 });
    expect(alert.textContent).toContain("Selective restore needs an archive");
    expect(alert.textContent).toContain("plain SQL");
  });
});
