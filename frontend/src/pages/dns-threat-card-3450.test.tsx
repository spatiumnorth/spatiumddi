/**
 * @vitest-environment jsdom
 *
 * The Security tab's DNS tunneling card needs read on servers (#3450): a
 * user without it must not ask the summary (each ask a 403 and a denied
 * audit row, every 60 s), and the card says why it is missing.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const summary = vi.fn();
let grants: {
  action: string;
  resource_type: string;
  resource_id?: string | null;
}[] = [];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: () =>
        Promise.resolve({
          is_superadmin: false,
          grants: grants.map((g) => ({ resource_id: null, ...g })),
        }),
    },
    dnsThreatApi: {
      ...actual.dnsThreatApi,
      summary: (...a: unknown[]) => summary(...a),
    },
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

import { DNSThreatCard } from "./DashboardPage";

afterEach(() => {
  cleanup();
  summary.mockReset();
});

async function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DNSThreatCard />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
}

describe("DNSThreatCard permission gate (#3450)", () => {
  it("does not ask the summary without read on servers, and says why", async () => {
    grants = [
      { action: "write", resource_type: "subnet" },
      { action: "read", resource_type: "dns_zone" },
    ];
    await show();
    expect(summary).not.toHaveBeenCalled();
    expect(screen.getByText(/needs read on servers/)).toBeTruthy();
  });

  it("asks the summary with read on servers", async () => {
    grants = [{ action: "read", resource_type: "server" }];
    summary.mockResolvedValue({
      has_data: true,
      suspicious_clients: 0,
      clients_seen: 3,
      worst_client_ip: null,
      worst_client_score: null,
      worst_client_parent: null,
    });
    await show();
    expect(summary).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/read on servers/)).toBeNull();
  });

  it("does not ask with a read grant scoped to one server", async () => {
    // The route checks read on the whole type; a scoped grant is refused.
    grants = [{ action: "read", resource_type: "server", resource_id: "abc" }];
    await show();
    expect(summary).not.toHaveBeenCalled();
    expect(screen.getByText(/needs read on servers/)).toBeTruthy();
  });

  it("asks the summary with a wildcard grant", async () => {
    grants = [{ action: "*", resource_type: "*" }];
    summary.mockResolvedValue({
      has_data: false,
      suspicious_clients: 0,
      clients_seen: 0,
      worst_client_ip: null,
      worst_client_score: null,
      worst_client_parent: null,
    });
    await show();
    expect(summary).toHaveBeenCalledTimes(1);
  });

  it("stops asking once the summary is refused", async () => {
    // The grant list is cached, so a read revoked mid-session still passes
    // ``can``: the poll itself must stop on the first 403.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      grants = [{ action: "read", resource_type: "server" }];
      summary.mockRejectedValue(
        Object.assign(new Error("Forbidden"), {
          isAxiosError: true,
          response: { status: 403, data: { detail: "Permission denied" } },
        }),
      );
      await show();
      expect(summary).toHaveBeenCalledTimes(1);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(130_000);
      });
      expect(summary).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
