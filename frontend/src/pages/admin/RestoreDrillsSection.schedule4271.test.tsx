/**
 * @vitest-environment jsdom
 *
 * The Drill schedule dialog reads the destination when it opens and sends only
 * what the operator changed (#4271, #4236's class).
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
import type { BackupTarget } from "@/lib/api";

const list = vi.fn<() => Promise<BackupTarget[]>>();
const update = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    formatApiError: actual.formatApiError,
    backupTargetsApi: {
      list,
      update,
      drillReadiness: vi.fn().mockResolvedValue([]),
      listDrills: vi.fn().mockResolvedValue([]),
      drillRun: vi.fn(),
    },
  };
});

const { RestoreDrillsSection } = await import("./RestoreDrillsSection");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const row = (over: Partial<BackupTarget>): BackupTarget =>
  ({
    id: "t1",
    name: "dest-1",
    kind: "azure_blob",
    enabled: true,
    drill_enabled: false,
    drill_cron: "0 4 1 1 *",
    ...over,
  }) as BackupTarget;

async function open() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <RestoreDrillsSection />
    </QueryClientProvider>,
  );
  fireEvent.click(await screen.findByRole("button", { name: "Schedule" }));
}

describe("Drill schedule dialog (#4271)", () => {
  it("reads the destination fresh when it opens", async () => {
    list.mockResolvedValueOnce([row({})]);
    list.mockResolvedValue([row({ drill_enabled: true })]);
    await open();
    const box = (await screen.findByRole("checkbox")) as HTMLInputElement;
    expect(box.checked).toBe(true);
  });

  it("an untouched Save sends nothing and closes", async () => {
    list.mockResolvedValue([row({ drill_enabled: true })]);
    await open();
    await screen.findByRole("checkbox");
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(screen.queryByRole("checkbox")).toBeNull());
    expect(update).not.toHaveBeenCalled();
  });

  it("sends only the changed cron, not the drill switch", async () => {
    list.mockResolvedValue([row({ drill_enabled: true })]);
    update.mockResolvedValue(row({}));
    await open();
    await screen.findByRole("checkbox");
    fireEvent.change(screen.getByPlaceholderText("0 5 * * 0"), {
      target: { value: "0 3 * * 1" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(update).toHaveBeenCalled());
    expect(update).toHaveBeenCalledWith("t1", { drill_cron: "0 3 * * 1" });
  });

  it("sends only the switch when only it changed", async () => {
    list.mockResolvedValue([row({})]);
    update.mockResolvedValue(row({}));
    await open();
    fireEvent.click(await screen.findByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(update).toHaveBeenCalled());
    expect(update).toHaveBeenCalledWith("t1", { drill_enabled: true });
  });

  it("blocks Save while enabled with an empty schedule (#4450)", async () => {
    list.mockResolvedValue([row({ drill_enabled: true })]);
    await open();
    await screen.findByRole("checkbox");
    fireEvent.change(screen.getByPlaceholderText("0 5 * * 0"), {
      target: { value: "" },
    });
    const save = screen.getByRole("button", { name: "Save" });
    expect((save as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/never runs/)).toBeTruthy();
    fireEvent.click(screen.getByRole("checkbox"));
    expect((save as HTMLButtonElement).disabled).toBe(false);
  });
});
