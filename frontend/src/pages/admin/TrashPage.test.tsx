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

describe("a restore that leaves rows behind (#3187)", () => {
  it("says which rows stayed in the Trash and why, instead of closing", async () => {
    list.mockResolvedValue({ items: [entry(2)], total: 1 });
    restore.mockResolvedValue({
      batch_id: "b-1",
      restored: 1,
      skipped: [
        {
          type: "dns_record",
          id: "r-2",
          display: "cn.example.test. CNAME",
          reason: "cn.example.test is an A record, so it can hold no CNAME",
        },
      ],
      held_back: [],
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
    await screen.findByText(/left in the Trash/);
    expect(screen.getByText(/cn\.example\.test\. CNAME — /)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Close" })).toBeTruthy();
  });
});

describe("a zone restore that holds records back (#3188)", () => {
  it("names the held subnet and the server's reason", async () => {
    list.mockResolvedValue({ items: [entry(3)], total: 1 });
    restore.mockResolvedValue({
      batch_id: "b-1",
      restored: 1,
      skipped: [],
      held_back: [
        {
          type: "subnet",
          id: "s-1",
          display: "2 IPAM records of 10.198.136.0/24 (name)",
          reason:
            "subnet 10.198.136.0/24 (name) is in the Trash — its records stay there with it and come back when it is restored",
        },
      ],
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
    await screen.findByText(/left in the Trash/);
    expect(
      screen.getByText(/2 IPAM records of 10\.198\.136\.0\/24 \(name\) — /),
    ).toBeTruthy();
  });
});

describe("a restore that leaves nothing behind", () => {
  it("still closes the dialog", async () => {
    list.mockResolvedValue({ items: [entry(2)], total: 1 });
    restore.mockResolvedValue({
      batch_id: "b-1",
      restored: 2,
      skipped: [],
      held_back: [],
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
    await waitFor(() =>
      expect(screen.queryByText("Restore from trash?")).toBeNull(),
    );
    expect(screen.queryByText(/left in the Trash/)).toBeNull();
  });
});

const heldBack = {
  batch_id: "b",
  restored: 1,
  skipped: [],
  held_back: [
    {
      type: "subnet",
      id: "s-1",
      display: "2 IPAM records of 10.198.136.0/24 (name)",
      reason: "subnet is in the Trash",
    },
  ],
};

function parentConflict(type: string, id: string, display: string) {
  return {
    response: {
      status: 409,
      data: {
        detail: {
          skip_conflicts_allowed: false,
          conflicts: [
            {
              type: "dns_record",
              id: "r-1",
              display: "ya.example.test. A",
              reason: `its parent ${display} is in the Trash`,
              parent_type: type,
              parent_id: id,
              parent_display: display,
            },
          ],
        },
      },
    },
  };
}

// Opens the row's dialog and presses Restore, which is refused for a parent in
// the Trash; leaves the dialog offering "Restore {display} first".
async function openParentFirst(
  type = "dns_zone",
  id = "z-9",
  display = "example.test.",
) {
  list.mockResolvedValue({ items: [entry(1)], total: 1 });
  restore.mockRejectedValueOnce(parentConflict(type, id, display));
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
  await screen.findByText(`Restore ${display} first`);
}

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

  it("keeps the dialog open and lists what the parent's restore left behind (#3505)", async () => {
    list.mockResolvedValue({ items: [entry(1)], total: 1 });
    restore.mockRejectedValueOnce({
      response: {
        status: 409,
        data: {
          detail: {
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
    restore.mockResolvedValueOnce({
      batch_id: "b",
      restored: 1,
      skipped: [],
      held_back: [
        {
          type: "subnet",
          id: "s-1",
          display: "2 IPAM records of 10.198.136.0/24 (name)",
          reason: "subnet is in the Trash",
        },
      ],
    });
    restore.mockResolvedValueOnce({ batch_id: "b", restored: 1, skipped: [] });
    fireEvent.click(first);
    await screen.findByText(/left in the Trash/);
    expect(
      screen.getByText(/2 IPAM records of 10\.198\.136\.0\/24 \(name\) — /),
    ).toBeTruthy();
    expect(restore).toHaveBeenCalledTimes(3);
  });

  it("still lists the parent's leftovers when the row's retry then fails (#3505)", async () => {
    await openParentFirst();
    restore.mockResolvedValueOnce(heldBack);
    restore.mockRejectedValueOnce(conflict(false));
    fireEvent.click(screen.getByText("Restore example.test. first"));
    await screen.findByText(/An active zone 'example\.test\.' already exists/);
    expect(screen.getByText(/left in the Trash/)).toBeTruthy();
    expect(
      screen.getByText(/2 IPAM records of 10\.198\.136\.0\/24/),
    ).toBeTruthy();
    // The row was not restored, so the dialog still offers to retry it.
    // (The table's own row button is named Restore too, hence two.)
    expect(screen.getAllByRole("button", { name: "Restore" })).toHaveLength(2);
  });

  it("keeps offering a further trashed ancestor after one left rows behind (#3505)", async () => {
    // subnet -> block -> space: the block's restore is refused for its space,
    // the space comes back holding a row back, the subnet's retry is refused
    // for the block, and the block must still be offered.
    await openParentFirst("ip_block", "blk-1", "10.0.0.0/8");
    restore.mockRejectedValueOnce(
      parentConflict("ip_space", "sp-1", "Lab space"),
    );
    fireEvent.click(screen.getByText("Restore 10.0.0.0/8 first"));
    const space = await screen.findByText("Restore Lab space first");
    restore.mockResolvedValueOnce(heldBack);
    restore.mockRejectedValueOnce(
      parentConflict("ip_block", "blk-1", "10.0.0.0/8"),
    );
    fireEvent.click(space);
    const block = await screen.findByText("Restore 10.0.0.0/8 first");
    expect(
      screen.getByText(/2 IPAM records of 10\.198\.136\.0\/24/),
    ).toBeTruthy();
    restore.mockResolvedValueOnce({ batch_id: "b", restored: 1, skipped: [] });
    restore.mockResolvedValueOnce({ batch_id: "b", restored: 1, skipped: [] });
    fireEvent.click(block);
    await screen.findByRole("button", { name: "Close" });
    expect(
      screen.getByText(/2 IPAM records of 10\.198\.136\.0\/24/),
    ).toBeTruthy();
    // row, block, space, row, block, row.
    expect(restore).toHaveBeenCalledTimes(6);
    expect(restore.mock.calls.map((c) => c[0])).toEqual([
      "dns_record",
      "ip_block",
      "ip_space",
      "dns_record",
      "ip_block",
      "dns_record",
    ]);
  });

  it("shows the parent's own failure and does not retry the row (#3505)", async () => {
    await openParentFirst();
    restore.mockRejectedValueOnce({
      response: { status: 422, data: { detail: "zone restore refused" } },
    });
    fireEvent.click(screen.getByText("Restore example.test. first"));
    await screen.findByText("zone restore refused");
    expect(restore).toHaveBeenCalledTimes(2);
    expect(screen.queryByText(/left in the Trash/)).toBeNull();
  });

  it("does not carry one dialog's parent leftovers into the next (#3505)", async () => {
    await openParentFirst();
    restore.mockResolvedValueOnce(heldBack);
    restore.mockResolvedValueOnce({ batch_id: "b", restored: 1, skipped: [] });
    fireEvent.click(screen.getByText("Restore example.test. first"));
    await screen.findByText(/left in the Trash/);
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() =>
      expect(screen.queryByText("Restore from trash?")).toBeNull(),
    );
    // Reopen and restore cleanly: nothing was left this time, so it closes.
    restore.mockResolvedValueOnce({ batch_id: "b", restored: 1, skipped: [] });
    fireEvent.click(screen.getByText("Restore"));
    const buttons = await screen.findAllByRole("button", { name: "Restore" });
    fireEvent.click(buttons[buttons.length - 1]);
    await waitFor(() =>
      expect(screen.queryByText("Restore from trash?")).toBeNull(),
    );
    expect(screen.queryByText(/left in the Trash/)).toBeNull();
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
  it("sends a search of only spaces as no search (#2737)", async () => {
    list.mockResolvedValue({
      items: [entry(1)],
      total: 1,
      limit: 100,
      offset: 0,
    });
    mount();
    await screen.findByText(/of 1/);
    fireEvent.change(screen.getByPlaceholderText("Search name / CIDR…"), {
      target: { value: "   " },
    });
    await waitFor(() =>
      expect(list).toHaveBeenLastCalledWith(
        expect.objectContaining({ q: undefined }),
      ),
    );
    expect(screen.queryByText("Trash is empty.")).toBeNull();
    expect(screen.queryByText("No rows match these filters.")).toBeNull();
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
