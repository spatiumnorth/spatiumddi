/**
 * @vitest-environment jsdom
 *
 * Backup page UI fixes: #2200 (destination copy), #2202 (restore warning
 * follows the mode), #2203 (API reason shown, not axios's status line),
 * #2204 (a non-superadmin is offered no writes; a refused read is not "empty").
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const me = vi.fn();
const list = vi.fn();
const previewManifest = vi.fn();
const restore = vi.fn();
const drillReadiness = vi.fn();
const listDrills = vi.fn();
const update = vi.fn();
const runNow = vi.fn();
const testTarget = vi.fn();

function refusal(status: number, detail: string) {
  return Object.assign(new Error(`Request failed with status code ${status}`), {
    response: { status, data: { detail } },
  });
}

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    formatApiError: actual.formatApiError,
    authApi: { me },
    backupApi: { previewManifest, restore },
    backupTargetsApi: {
      list,
      drillReadiness,
      listDrills,
      update,
      runNow,
      test: testTarget,
    },
  };
});
vi.mock("./BackupSectionsPicker", () => ({
  BackupSectionsPicker: ({
    onModeChange,
  }: {
    onModeChange: (m: "full" | "selective") => void;
  }) => (
    <button type="button" onClick={() => onModeChange("selective")}>
      choose-selective
    </button>
  ),
}));
vi.mock("./FactoryResetSection", () => ({ FactoryResetSection: () => null }));

const { BackupPage } = await import("./BackupPage");

function withClient(ui: ReactElement) {
  return render(
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
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function pickFile() {
  const input = document.querySelector(
    'input[type="file"]',
  ) as HTMLInputElement;
  const f = new File(["x"], "x.zip");
  fireEvent.change(input, { target: { files: [f] } });
}

describe("Backup page", () => {
  it("shows the API's reason when a manifest preview is refused (#2203)", async () => {
    me.mockResolvedValue({ is_superadmin: true });
    list.mockResolvedValue([]);
    previewManifest.mockRejectedValue(
      refusal(400, "archive is malformed: File is not a zip file"),
    );
    withClient(<BackupPage />);
    await screen.findByText("Restore from file");
    pickFile();
    await waitFor(() =>
      expect(
        screen.getByText("archive is malformed: File is not a zip file"),
      ).toBeTruthy(),
    );
    expect(screen.queryByText(/status code 400/)).toBeNull();
  });

  it("shows the API's reason for an empty archive (422)", async () => {
    me.mockResolvedValue({ is_superadmin: true });
    previewManifest.mockRejectedValue(refusal(422, "archive is empty"));
    withClient(<BackupPage />);
    await screen.findByText("Restore from file");
    pickFile();
    await waitFor(() =>
      expect(screen.getByText("archive is empty")).toBeTruthy(),
    );
  });

  it("restore warning follows the mode (#2202)", async () => {
    me.mockResolvedValue({ is_superadmin: true });
    previewManifest.mockResolvedValue({
      manifest: { hostname: "h", format_version: 2 },
      format_recognised: true,
      archive_bytes: 1024,
    });
    withClient(<BackupPage />);
    await screen.findByText("Restore from file");
    expect(
      screen.getByText(/Every table on this install is replaced/),
    ).toBeTruthy();
    pickFile();
    fireEvent.click(await screen.findByText("choose-selective"));
    await waitFor(() =>
      expect(
        screen.queryByText(/Every table on this install is replaced/),
      ).toBeNull(),
    );
    expect(screen.getByText(/Only the sections you tick/)).toBeTruthy();
  });

  it("names the destination kinds honestly (#2200)", async () => {
    me.mockResolvedValue({ is_superadmin: true });
    list.mockResolvedValue([]);
    withClient(<BackupPage />);
    await screen.findByText("Restore from file");
    // Names no kind rather than a subset of the ten the API offers.
    expect(document.body.textContent).not.toMatch(
      /local volume|S3|SCP|Azure|network share|object store/i,
    );
    fireEvent.click(screen.getByRole("button", { name: "Destinations" }));
    await screen.findByText(/No backup targets configured/);
    expect(document.body.textContent).not.toMatch(/local volume/i);
  });

  it("shows the API's reason when a drill schedule is refused (#2203)", async () => {
    me.mockResolvedValue({ is_superadmin: true });
    list.mockResolvedValue([
      {
        id: "t1",
        name: "local",
        kind: "local_volume",
        drill_last_status: "never",
      },
    ]);
    drillReadiness.mockResolvedValue({ targets: [] });
    listDrills.mockResolvedValue([]);
    update.mockRejectedValue(refusal(409, "a drill is already running"));
    withClient(<BackupPage />);
    await screen.findByText("Restore from file");
    fireEvent.click(screen.getByRole("button", { name: "Restore Drills" }));
    fireEvent.click(await screen.findByRole("button", { name: "Schedule" }));
    fireEvent.click(await screen.findByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(screen.getByText("a drill is already running")).toBeTruthy(),
    );
    expect(screen.queryByText(/status code 409/)).toBeNull();
  });

  it("shows the API's reason when a target's run-now or test is refused (#2203)", async () => {
    me.mockResolvedValue({ is_superadmin: true });
    list.mockResolvedValue([
      { id: "t1", name: "nas", kind: "smb", enabled: true },
    ]);
    runNow.mockRejectedValue(refusal(409, "a run is already in progress"));
    testTarget.mockRejectedValue(refusal(404, "backup target not found"));
    withClient(<BackupPage />);
    await screen.findByText("Restore from file");
    fireEvent.click(screen.getByRole("button", { name: "Destinations" }));
    fireEvent.click(await screen.findByTitle("Run now"));
    await waitFor(() =>
      expect(screen.getByText("a run is already in progress")).toBeTruthy(),
    );
    expect(screen.queryByText(/status code 409/)).toBeNull();
    fireEvent.click(screen.getByTitle("Test connection"));
    await waitFor(() =>
      expect(screen.getByText("backup target not found")).toBeTruthy(),
    );
    expect(screen.queryByText(/status code 404/)).toBeNull();
  });

  it("offers a Viewer no Add target and does not call a refused read empty (#2204)", async () => {
    me.mockResolvedValue({ is_superadmin: false });
    list.mockRejectedValue(refusal(403, "Superadmin required"));
    drillReadiness.mockRejectedValue(refusal(403, "Superadmin required"));
    listDrills.mockRejectedValue(refusal(403, "Superadmin required"));
    withClient(<BackupPage />);
    await screen.findByText(/don.t have permission to use backup/);
    fireEvent.click(screen.getByRole("button", { name: "Destinations" }));
    const add = await screen.findByRole("button", { name: /Add target/ });
    expect(add.matches(":disabled")).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Restore Drills" }));
    await screen.findByText(/permission to see backup targets/i);
    expect(screen.queryByText(/No backup targets configured yet/)).toBeNull();
  });
});
