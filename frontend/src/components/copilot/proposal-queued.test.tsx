/**
 * @vitest-environment jsdom
 *
 * A Copilot proposal the two-person approval gate queued is not "approved"
 * (#1915).
 *
 * Applying a risky proposal (delete subnet / block / space / zone / scope /
 * group) goes through the same gate as the REST delete. When a policy
 * matches, the server stamps `applied_at` and returns
 * `result.queued_for_approval` — nothing has changed yet. The card read
 * `applied_at` alone and showed a green "approved" badge.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { AIProposal } from "@/lib/api";

let proposal: Partial<AIProposal> = {};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    aiApi: {
      ...actual.aiApi,
      getProposal: () => Promise.resolve(proposal),
    },
  };
});

const { ProposalCard } = await import("./CopilotDrawer");

afterEach(cleanup);

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <ProposalCard
        proposalId="p-1"
        operation="delete_subnet"
        previewText="Soft-delete subnet 10.73.5.0/24"
      />
    </QueryClientProvider>,
  );
}

const base = {
  id: "p-1",
  operation: "delete_subnet",
  preview_text: "Soft-delete subnet 10.73.5.0/24",
  applied_at: "2026-10-14T00:00:00.000Z",
  discarded_at: null,
  expires_at: "2999-01-01T00:00:00.000Z",
  error: null,
};

describe("a Copilot proposal", () => {
  it("the approval queue took says it awaits approval, not approved", async () => {
    proposal = {
      ...base,
      result: {
        queued_for_approval: true,
        change_request_id: "cr-1",
        state: "pending",
      },
    };
    show();
    expect(await screen.findByText("awaiting approval")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toMatch(
      /Submitted for approval/,
    );
    expect(screen.queryByText("approved")).toBeNull();
  });

  it("that ran still reads approved", async () => {
    proposal = { ...base, result: { deleted: true } };
    show();
    expect(await screen.findByText("approved")).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull();
  });
});
