/**
 * @vitest-environment jsdom
 *
 * #4864: a row's own Snooze removes that row's button when the list is read
 * again; focus must land on the next row's Snooze, never the page body.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AggregationCandidatesBadge } from "./AggregationSuggestions";

const cand = (key: string, net: string) => ({
  supernet: net,
  prefix_len: 24,
  total_size: 256,
  subnet_ids: [],
  subnet_networks: [],
  candidate_key: key,
  snoozed_until: null,
});

let rows = [cand("a", "10.0.0.0/24"), cand("b", "10.0.1.0/24")];

vi.mock("@/lib/api", () => ({
  ipamApi: {
    blockAggregationSuggestions: vi.fn(async () => rows),
    snoozeAggregationCandidate: vi.fn(async (key: string) => {
      rows = rows.filter((r) => r.candidate_key !== key);
    }),
    dismissAggregationCandidate: vi.fn(),
    clearAggregationSnooze: vi.fn(),
  },
}));
vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ can: () => true }),
  permissionGate: () => ({}),
}));

afterEach(() => {
  cleanup();
  sessionStorage.clear();
  rows = [cand("a", "10.0.0.0/24"), cand("b", "10.0.1.0/24")];
});

describe("aggregation row Snooze (#4864)", () => {
  it("hands focus to the next row's Snooze after the row goes", async () => {
    sessionStorage.setItem(
      "ipam-aggregation-popover-blk",
      JSON.stringify(true),
    );
    render(
      <QueryClientProvider client={new QueryClient()}>
        <main>
          <AggregationCandidatesBadge blockId="blk" />
        </main>
      </QueryClientProvider>,
    );
    const first = (await screen.findAllByText("Snooze 30 days"))[0].closest(
      "button",
    )!;
    first.focus();
    await userEvent.click(first);
    await waitFor(() => expect(first.isConnected).toBe(false));
    await waitFor(() => {
      expect(document.activeElement).not.toBe(document.body);
      expect(document.activeElement?.textContent).toContain("Snooze 30 days");
    });
    expect(screen.getByText("10.0.1.0/24")).toBeTruthy();
  });
});
