/**
 * @vitest-environment jsdom
 *
 * The destination dialog sends a port / Object Lock period as a number
 * (#3946), so the API reads the same value whichever client sent it.
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
import type { BackupTarget, BackupTargetKind } from "@/lib/api";

const list = vi.fn<() => Promise<BackupTarget[]>>();
const listKinds = vi.fn<() => Promise<BackupTargetKind[]>>();
const create = vi.fn();
const update = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    formatApiError: actual.formatApiError,
    backupTargetsApi: { list, listKinds, create, update },
  };
});
vi.mock("./BackupSectionsPicker", () => ({ BackupSectionsPicker: () => null }));

const { BackupTargetsSection } = await import("./BackupTargetsSection");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const f = (name: string, label: string, required = false) => ({
  name,
  label,
  type: "text",
  required,
  description: null,
  secret: false,
});

const KINDS: BackupTargetKind[] = [
  {
    kind: "ftp",
    label: "FTP",
    inherently_write_only: false,
    config_fields: [
      f("host", "Host", true),
      f("port", "Port"),
      f("prefix", "Prefix"),
    ],
  },
];

function renderSection() {
  return render(
    <QueryClientProvider
      client={
        new QueryClient({
          defaultOptions: { queries: { retry: false } },
        })
      }
    >
      <BackupTargetsSection />
    </QueryClientProvider>,
  );
}

function input(container: HTMLElement, label: string): HTMLInputElement {
  const span = Array.from(container.querySelectorAll("span")).find((s) =>
    s.textContent?.startsWith(label),
  );
  return span!.closest("label")!.querySelector("input")!;
}

describe("backup destination Add sends a port as a number (#3946)", () => {
  it("a whole number goes out as a number, other text as typed", async () => {
    list.mockResolvedValue([]);
    listKinds.mockResolvedValue(KINDS);
    create.mockResolvedValue({});
    const { container } = renderSection();
    fireEvent.click(await screen.findByText("Add target"));
    await screen.findByText("FTP (ftp)");
    const select = container.querySelector("select") as HTMLSelectElement;
    fireEvent.change(select, { target: { value: "ftp" } });
    await screen.findByText("Host");
    fireEvent.change(input(container, "Host"), { target: { value: "h" } });
    fireEvent.change(input(container, "Port"), { target: { value: "2121" } });
    fireEvent.change(container.querySelector('input[type="text"]')!, {
      target: { value: "t1" },
    });
    const pass = Array.from(
      container.querySelectorAll('input[type="password"]'),
    ).at(-1) as HTMLInputElement;
    fireEvent.change(pass, { target: { value: "passphrase-123" } });
    fireEvent.submit(container.querySelector("form")!);
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create.mock.calls[0][0].config).toEqual({ host: "h", port: 2121 });
  });
});

const STORED: BackupTarget = {
  id: "t-1",
  name: "ftp-1",
  description: "",
  kind: "ftp",
  enabled: true,
  config: { host: "h", port: 21, prefix: null },
  passphrase_set: true,
  passphrase_hint: "",
  schedule_cron: null,
  retention_keep_last_n: null,
  retention_keep_days: null,
  write_only: false,
  last_run_status: "never",
  last_run_at: null,
  last_run_filename: null,
} as unknown as BackupTarget;

async function openEdit() {
  list.mockResolvedValue([STORED]);
  listKinds.mockResolvedValue(KINDS);
  update.mockResolvedValue({});
  const view = renderSection();
  fireEvent.click(await screen.findByTitle(/edit/i));
  await screen.findByText("Prefix");
  return view;
}

describe("backup destination Edit round-trips stored types (#3947)", () => {
  it("shows a stored null as empty and an untouched Save sends no config", async () => {
    const { container } = await openEdit();
    expect(input(container, "Prefix").value).toBe("");
    expect(input(container, "Port").value).toBe("21");
    fireEvent.submit(container.querySelector("form")!);
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update.mock.calls[0][1].config).toBeUndefined();
  });

  it("sends only the setting that changed, as a number", async () => {
    const { container } = await openEdit();
    fireEvent.change(input(container, "Port"), { target: { value: "2121" } });
    fireEvent.submit(container.querySelector("form")!);
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update.mock.calls[0][1].config).toEqual({ port: 2121 });
  });
});
