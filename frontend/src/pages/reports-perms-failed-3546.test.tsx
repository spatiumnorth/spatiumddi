/**
 * @vitest-environment jsdom
 *
 * A failed permissions read is not a missing grant: the Reports cards say
 * the permissions could not be read, and do not ask for their reports
 * (#3546).
 */
import { act, cleanup, render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const calls = {
  topSubnetsByUtilization: vi.fn(),
  topOwnersByIpCount: vi.fn(),
  topModifiedResources: vi.fn(),
  topDnsClients: vi.fn(),
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: () => Promise.reject(new Error("Network Error")),
    },
    reportsApi: calls,
  };
});

const { ReportsPage } = await import("@/pages/ReportsPage");

afterEach(cleanup);

describe("Reports page after a failed permissions read (#3546)", () => {
  it("says the permissions could not be read on every card", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <ReportsPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await act(async () => {
      await new Promise((r) => setTimeout(r, 300));
    });
    const text = document.body.textContent ?? "";
    expect(text.split("Your permissions could not be read").length - 1).toBe(4);
    expect(text).not.toContain("You don't have permission");
    for (const fn of Object.values(calls)) expect(fn).not.toHaveBeenCalled();
  });
});
