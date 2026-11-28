/**
 * @vitest-environment jsdom
 *
 * A refused archive preview and a failed Test connection are announced
 * (role="alert"), not drawn in a bare red box (#4819).
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

const previewManifest = vi.fn();
const list = vi.fn();
const test = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    backupApi: { ...actual.backupApi, previewManifest },
    backupTargetsApi: { list, test },
  };
});
vi.mock("./BackupSectionsPicker", () => ({ BackupSectionsPicker: () => null }));
vi.mock("./FactoryResetSection", () => ({ FactoryResetSection: () => null }));
vi.mock("./RestoreDrillsSection", () => ({
  RestoreDrillsSection: () => null,
}));

const { BackupPage } = await import("./BackupPage");
const { BackupTargetsSection } = await import("./BackupTargetsSection");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const wrap = (ui: React.ReactNode) => (
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
    {ui}
  </QueryClientProvider>
);

function pick(container: HTMLElement) {
  fireEvent.change(container.querySelector('input[type="file"]')!, {
    target: {
      files: [new File(["zip"], "a.zip", { type: "application/zip" })],
    },
  });
}

describe("failed backup actions are announced (#4819)", () => {
  it("announces a refused archive preview", async () => {
    previewManifest.mockRejectedValueOnce({
      isAxiosError: true,
      response: {
        status: 400,
        data: { detail: "archive is malformed: File is not a zip file" },
      },
    });
    const { container } = render(wrap(<BackupPage />));
    pick(container);
    const alert = await screen.findByRole("alert", {}, { timeout: 10000 });
    expect(alert.textContent).toContain("archive is malformed");
  });

  it("announces an archive the restore refuses", async () => {
    previewManifest.mockResolvedValueOnce({
      manifest: { format: "spatiumddi-backup", format_version: 2 },
      archive_bytes: 100,
      format_recognised: true,
      restorable: false,
      restore_refusal: "archive is missing required member: secrets.enc",
    });
    const { container } = render(wrap(<BackupPage />));
    pick(container);
    const alert = await screen.findByRole("alert", {}, { timeout: 10000 });
    expect(alert.textContent).toContain("secrets.enc");
  });

  it("announces a Test connection that answers ok: false", async () => {
    list.mockResolvedValue([
      {
        id: "t-1",
        name: "testnet-1",
        description: "",
        kind: "scp",
        enabled: false,
        config: {},
        passphrase_set: true,
        passphrase_hint: "",
        schedule_cron: null,
        last_run_status: "never",
        drill_last_status: "never",
      },
    ]);
    test.mockResolvedValueOnce({
      ok: false,
      error: "SSH connect failed: timed out",
    });
    render(wrap(<BackupTargetsSection />));
    fireEvent.click(await screen.findByTitle("Test connection"));
    await waitFor(
      () =>
        expect(screen.getByRole("alert").textContent).toContain(
          "SSH connect failed",
        ),
      { timeout: 10000 },
    );
  });
});
