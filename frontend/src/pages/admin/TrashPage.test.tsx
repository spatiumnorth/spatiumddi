/**
 * @vitest-environment jsdom
 *
 * "Restore the others" is offered only where the server accepts it (#1960).
 *
 * A record row of a deleted zone's batch is a `dns_record` like the rows of a
 * flat bulk delete, so the clicked row's type cannot tell the two apart: the
 * 409 carries `skip_conflicts_allowed`, and the page follows it.
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
import type { TrashEntry } from "@/lib/api";

const list = vi.fn();
const restore = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, trashApi: { list, restore, permanentDelete: vi.fn() } };
});

const { TrashPage } = await import("./TrashPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function entry(batchSize: number): TrashEntry {
  return {
    id: "r-1",
    type: "dns_record",
    name_or_cidr: "ya.example.test. A",
    deleted_at: "2026-10-15T00:00:00Z",
    deleted_by_user_id: null,
    deleted_by_username: "admin",
    deletion_batch_id: "b-1",
    batch_size: batchSize,
  };
}

function conflict(allowed: boolean | undefined) {
  const detail: Record<string, unknown> = {
    message: "Restore would clash with active rows",
    conflicts: [
      {
        type: "dns_zone",
        id: "z-1",
        display: "example.test.",
        reason: "An active zone 'example.test.' already exists",
      },
    ],
  };
  if (allowed !== undefined) detail.skip_conflicts_allowed = allowed;
  return { response: { status: 409, data: { detail } } };
}

async function clash(allowed: boolean | undefined) {
  list.mockResolvedValue({ items: [entry(3)], total: 1 });
  restore.mockRejectedValue(conflict(allowed));
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <TrashPage />
    </QueryClientProvider>,
  );
  fireEvent.click(await screen.findByText("Restore"));
  const buttons = await screen.findAllByRole("button", { name: "Restore" });
  fireEvent.click(buttons[buttons.length - 1]);
  await screen.findByText(/Cannot restore/);
}

describe("Restore the others (#1960)", () => {
  it("is not offered on a record row of a zone's batch", async () => {
    await clash(false);
    expect(screen.queryByText("Restore the others")).toBeNull();
  });

  it("is not offered when the server does not say it is allowed", async () => {
    await clash(undefined);
    expect(screen.queryByText("Restore the others")).toBeNull();
  });

  it("is offered on a flat batch, and sends skip_conflicts", async () => {
    await clash(true);
    restore.mockResolvedValue({ batch_id: "b-1", restored: 1, skipped: [] });
    fireEvent.click(screen.getByText("Restore the others"));
    await waitFor(() =>
      expect(restore).toHaveBeenLastCalledWith("dns_record", "r-1", {
        skipConflicts: true,
      }),
    );
  });
});

describe("the list (#1961, #1962)", () => {
  function mount() {
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <TrashPage />
      </QueryClientProvider>,
    );
  }

  it("says how many rows there are and pages to the rest", async () => {
    list.mockImplementation((p: { offset?: number }) =>
      Promise.resolve({
        items: [entry(1)],
        total: 305,
        limit: 100,
        offset: p.offset ?? 0,
      }),
    );
    mount();
    expect(await screen.findByText(/of 305/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText("Next page"));
    await waitFor(() =>
      expect(list).toHaveBeenLastCalledWith(
        expect.objectContaining({ offset: 100, limit: 100 }),
      ),
    );
  });

  it("can list the oldest rows first", async () => {
    list.mockResolvedValue({
      items: [entry(1)],
      total: 1,
      limit: 100,
      offset: 0,
    });
    mount();
    await screen.findByText(/of 1/);
    fireEvent.change(screen.getByLabelText("Order"), {
      target: { value: "oldest" },
    });
    await waitFor(() =>
      expect(list).toHaveBeenLastCalledWith(
        expect.objectContaining({ sort: "oldest", offset: 0 }),
      ),
    );
  });

  it("does not call a search with no matches an empty Trash", async () => {
    list.mockResolvedValue({ items: [], total: 0, limit: 100, offset: 0 });
    mount();
    expect(await screen.findByText("Trash is empty.")).toBeTruthy();
    fireEvent.change(screen.getByPlaceholderText("Search name / CIDR…"), {
      target: { value: "nothing-matches" },
    });
    expect(
      await screen.findByText("No rows match these filters."),
    ).toBeTruthy();
    expect(screen.queryByText("Trash is empty.")).toBeNull();
  });
});
