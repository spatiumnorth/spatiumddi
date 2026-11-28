/**
 * @vitest-environment jsdom
 *
 * #4801 — the NTP page shows each node's sync state; an unsynchronized node
 * reads as a calm "no time source reachable" note.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { NtpSyncState } from "./NtpSyncState";

const rows = vi.hoisted(() => ({ list: vi.fn() }));
vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  applianceApprovalApi: { list: rows.list },
}));

afterEach(cleanup);

const row = (over: Record<string, unknown>) => ({
  id: "1",
  hostname: "node-a",
  state: "approved",
  ntp_sync_state: null,
  ...over,
});

function renderIt() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <NtpSyncState />
    </QueryClientProvider>,
  );
}

describe("NtpSyncState", () => {
  it("shows a calm message for an unsynchronized node", async () => {
    rows.list.mockResolvedValue([row({ ntp_sync_state: "unsynchronized" })]);
    renderIt();
    expect(await screen.findByText(/No time source reachable/)).toBeTruthy();
    expect(screen.getByText("node-a")).toBeTruthy();
    expect(screen.getByText(/expected/).textContent).toContain("isolated");
  });

  it("shows synchronized without the isolated-network note", async () => {
    rows.list.mockResolvedValue([row({ ntp_sync_state: "synchronized" })]);
    renderIt();
    expect(await screen.findByText("Synchronized")).toBeTruthy();
    expect(screen.queryByText(/expected/)).toBeNull();
  });
});
