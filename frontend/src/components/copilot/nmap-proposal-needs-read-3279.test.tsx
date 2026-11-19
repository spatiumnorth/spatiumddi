/**
 * @vitest-environment jsdom
 *
 * Running a Copilot nmap-scan proposal takes write on 'manage_nmap_scans';
 * the live result under the card reads the scan back, which takes read. A
 * role holding only write is told it cannot see the progress instead of
 * polling a 403 behind a "Loading scan…" spinner that never ends (#3279).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { AIProposal } from "@/lib/api";

const proposal: Partial<AIProposal> = {
  id: "p-1",
  operation: "run_nmap_scan",
  preview_text: "Run nmap on 10.0.0.5",
  applied_at: "2026-10-14T00:00:00.000Z",
  discarded_at: null,
  expires_at: "2999-01-01T00:00:00.000Z",
  error: null,
  result: { id: "scan-1", status: "queued" },
};
let grants: [string, string][] = [];
const getScan = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    aiApi: { ...actual.aiApi, getProposal: () => Promise.resolve(proposal) },
    authApi: {
      ...actual.authApi,
      myPermissions: () =>
        Promise.resolve({
          is_superadmin: false,
          grants: grants.map(([action, resource_type]) => ({
            action,
            resource_type,
            resource_id: null,
          })),
        }),
    },
    nmapApi: { ...actual.nmapApi, getScan: (id: string) => getScan(id) },
  };
});

const { ProposalCard } = await import("./CopilotDrawer");

afterEach(() => {
  cleanup();
  getScan.mockReset();
});

async function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <ProposalCard
        proposalId="p-1"
        operation="run_nmap_scan"
        previewText="Run nmap on 10.0.0.5"
      />
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 80));
  });
}

describe("a Copilot nmap-scan proposal (#3279)", () => {
  it("tells a write-only role it cannot see the scan, and does not read it", async () => {
    grants = [["write", "manage_nmap_scans"]];
    await show();
    await screen.findByText(/don't have permission to see its progress/);
    expect(document.body.textContent).not.toMatch(/Loading scan/);
    expect(getScan).not.toHaveBeenCalled();
  });

  it("shows the refusal rather than spinning when the read fails", async () => {
    grants = [
      ["write", "manage_nmap_scans"],
      ["read", "manage_nmap_scans"],
    ];
    getScan.mockRejectedValue({
      response: { status: 403, data: { detail: "need 'read'" } },
    });
    await show();
    await screen.findByText(/need 'read'/);
    expect(document.body.textContent).not.toMatch(/Loading scan/);
  });

  it("reads the scan for a role holding read", async () => {
    grants = [
      ["write", "manage_nmap_scans"],
      ["read", "manage_nmap_scans"],
    ];
    getScan.mockReturnValue(new Promise(() => {}));
    await show();
    await waitFor(() => expect(getScan).toHaveBeenCalledWith("scan-1"));
    expect(document.body.textContent).toMatch(/Loading scan/);
  });
});
