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

describe("a parent still in the Trash (#1957)", () => {
  it("offers to restore the parent first, then restores this row", async () => {
    list.mockResolvedValue({ items: [entry(1)], total: 1 });
    restore.mockRejectedValueOnce({
      response: {
        status: 409,
        data: {
          detail: {
            message: "Restore would clash with active rows",
            skip_conflicts_allowed: true,
            conflicts: [
              {
                type: "dns_record",
                id: "r-1",
                display: "ya.example.test. A",
                reason: "its zone example.test. is in the Trash",
                parent_type: "dns_zone",
                parent_id: "z-9",
                parent_display: "example.test.",
              },
            ],
          },
        },
      },
    });
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
    const first = await screen.findByText("Restore example.test. first");
    restore.mockResolvedValue({ batch_id: "b", restored: 1, skipped: [] });
    fireEvent.click(first);
    await waitFor(() => expect(restore).toHaveBeenCalledTimes(3));
    expect(restore.mock.calls[1]).toEqual(["dns_zone", "z-9"]);
    expect(restore.mock.calls[2]).toEqual([
      "dns_record",
      "r-1",
      { skipConflicts: false },
    ]);
  });

  it("is not offered when the clash is not a trashed parent", async () => {
    await clash(false);
    expect(
      screen.queryByRole("button", { name: /^Restore .* first$/ }),
    ).toBeNull();
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

  it("steps back when the page it is on empties", async () => {
    let total = 105;
    list.mockImplementation((p: { offset?: number }) =>
      Promise.resolve({
        items: (p.offset ?? 0) >= total ? [] : [entry(1)],
        total,
        limit: 100,
        offset: p.offset ?? 0,
      }),
    );
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <TrashPage />
      </QueryClientProvider>,
    );
    await screen.findByText(/of 105/);
    fireEvent.click(screen.getByLabelText("Next page"));
    await screen.findByText(/101–101 of 105/);
    total = 100; // the rows on page 2 were restored or purged
    await qc.invalidateQueries({ queryKey: ["trash"] });
    await waitFor(() =>
      expect(list).toHaveBeenLastCalledWith(
        expect.objectContaining({ offset: 0 }),
      ),
    );
    expect(screen.queryByText("Trash is empty.")).toBeNull();
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

describe("Delete permanently names what goes with the row (#2602)", () => {
  async function openDelete(type: TrashEntry["type"], batchSize: number) {
    list.mockResolvedValue({
      items: [{ ...entry(batchSize), type, name_or_cidr: "row-x" }],
      total: 1,
      limit: 100,
      offset: 0,
    });
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <TrashPage />
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByText("Delete"));
    return (await screen.findByText(/This permanently removes/)).textContent;
  }

  it("names a subnet's scopes, addresses and records, and does not count the batch", async () => {
    const t = await openDelete("subnet", 4);
    expect(t).toMatch(/DHCP scopes \(with their pools and static/);
    expect(t).toMatch(/addresses and the DNS records published for them/);
    expect(t).not.toMatch(/other row/);
  });

  it("names a zone's records and pools", async () => {
    const t = await openDelete("dns_zone", 3);
    expect(t).toMatch(/All of its DNS records and its DNS pools/);
    expect(t).not.toMatch(/other row/);
  });

  it("adds no count for a row deleted alone", async () => {
    const t = await openDelete("dns_zone", 1);
    expect(t).not.toMatch(/other row/);
  });
});
