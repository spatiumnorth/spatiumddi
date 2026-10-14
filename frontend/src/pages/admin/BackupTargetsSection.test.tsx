/**
 * @vitest-environment jsdom
 *
 * Backup targets on a multi-node appliance (#1838).
 *
 * A `local_volume` target is per node there, and the server says so three
 * ways: `last_run_node` on the target, `node_name` per archive, and an
 * `X-Archive-Listing-Note` header on the listing. A restore answered by the
 * wrong node is a 502 whose `detail` names the node holding the archive.
 * None of that helps if the page drops it, and the old page did: it showed
 * neither field, never read the header, and rendered axios's
 * "Request failed with status code 502" instead of the detail.
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
import type { BackupArchiveList, BackupTarget } from "@/lib/api";

const list = vi.fn<() => Promise<BackupTarget[]>>();
const listArchives = vi.fn<() => Promise<BackupArchiveList>>();
const restoreFromArchive = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    formatApiError: actual.formatApiError,
    backupTargetsApi: { list, listArchives, restoreFromArchive },
  };
});
vi.mock("./BackupSectionsPicker", () => ({ BackupSectionsPicker: () => null }));

const { BackupTargetsSection } = await import("./BackupTargetsSection");

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

const ARCHIVE = "spatiumddi-backup-api-s4cl7-20261013-065126-a1a455.zip";

function target(overrides: Partial<BackupTarget> = {}): BackupTarget {
  return {
    id: "t-1",
    name: "local",
    description: "",
    kind: "local_volume",
    enabled: true,
    config: { path: "/var/lib/spatiumddi/backups" },
    passphrase_set: true,
    passphrase_hint: "",
    schedule_cron: null,
    retention_keep_last_n: null,
    retention_keep_days: null,
    write_only: false,
    last_run_status: "success",
    last_run_at: "2026-10-13T06:51:26Z",
    last_run_filename: ARCHIVE,
    last_run_node: "ddipg-member-1",
    last_run_bytes: 1024,
    last_run_duration_ms: 10,
    last_run_error: null,
    next_run_at: null,
    drill_enabled: false,
    drill_cron: null,
    drill_next_run_at: null,
    drill_last_status: "never",
    drill_last_at: null,
    created_at: "2026-10-13T00:00:00Z",
    modified_at: "2026-10-13T00:00:00Z",
    ...overrides,
  };
}

async function expand() {
  fireEvent.click(await screen.findByTitle("Expand archives"));
}

describe("BackupTargetsSection on a multi-node appliance (#1838)", () => {
  it("names the node that wrote the last archive", async () => {
    list.mockResolvedValue([target()]);
    withClient(<BackupTargetsSection />);
    expect(await screen.findByText("ddipg-member-1")).toBeTruthy();
  });

  it("shows the listing note and each archive's node", async () => {
    list.mockResolvedValue([target()]);
    listArchives.mockResolvedValue({
      archives: [
        {
          filename: "spatiumddi-backup-old.zip",
          size_bytes: 10,
          created_at: "2026-10-01T00:00:00Z",
          node_name: "ddipg-member-2",
        },
      ],
      note: "The last backup was written on node ddipg-member-1 and is held there, not missing.",
    });
    withClient(<BackupTargetsSection />);
    await expand();
    expect((await screen.findByRole("note")).textContent).toContain(
      "held there, not missing",
    );
    expect(screen.getByText("ddipg-member-2")).toBeTruthy();
  });

  it("shows the note even when this node's list is empty", async () => {
    // The reported case: the archive is on another node, so this node's
    // directory is empty, and "No archives yet" alone reads as data loss.
    list.mockResolvedValue([target()]);
    listArchives.mockResolvedValue({
      archives: [],
      note: "held on ddipg-member-1",
    });
    withClient(<BackupTargetsSection />);
    await expand();
    expect((await screen.findByRole("note")).textContent).toContain(
      "held on ddipg-member-1",
    );
  });

  it("renders the server's restore refusal, not axios's status line", async () => {
    list.mockResolvedValue([target()]);
    listArchives.mockResolvedValue({
      archives: [
        {
          filename: ARCHIVE,
          size_bytes: 10,
          created_at: "2026-10-13T06:51:26Z",
          node_name: "ddipg-member-2",
        },
      ],
      note: null,
    });
    const detail =
      "archive not found. It was written on node ddipg-member-1, and this request was answered by the api on node ddipg-member-2.";
    restoreFromArchive.mockRejectedValue(
      Object.assign(new Error("Request failed with status code 502"), {
        response: { status: 502, data: { detail } },
      }),
    );
    withClient(<BackupTargetsSection />);
    await expand();
    fireEvent.click(await screen.findByTitle("Restore from this archive"));
    fireEvent.change(screen.getByPlaceholderText("RESTORE-FROM-BACKUP"), {
      target: { value: "RESTORE-FROM-BACKUP" },
    });
    const pass = document.querySelector(
      'input[type="password"]',
    ) as HTMLInputElement;
    fireEvent.change(pass, { target: { value: "hunter2hunter2" } });
    fireEvent.submit(pass.closest("form")!);
    await waitFor(() => expect(screen.getByText(detail)).toBeTruthy());
    expect(screen.queryByText(/status code 502/)).toBeNull();
  });
});
