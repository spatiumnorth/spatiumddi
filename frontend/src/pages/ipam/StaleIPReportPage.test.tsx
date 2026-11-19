/**
 * @vitest-environment jsdom
 *
 * Stale IPs page copy (#2421). Deprecating keeps the row, so the address
 * still counts as allocated and Next available skips it; the page must not
 * promise that it reclaims address space.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    ipamApi: {
      ...actual.ipamApi,
      listSpaces: () => Promise.resolve([]),
      getStaleIPs: () =>
        Promise.resolve({ total: 0, items: [], stale_days: 90 }),
    },
  };
});

const { StaleIPReportPage } = await import("./StaleIPReportPage");

afterEach(cleanup);

describe("StaleIPReportPage copy", () => {
  it("does not promise that deprecating reclaims address space", () => {
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter>
          <StaleIPReportPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const text = container.textContent ?? "";
    expect(text).not.toMatch(/reclaim/i);
    expect(text).toMatch(/still counts as allocated/);
    expect(text).toMatch(/Delete the row to free the address/);
    expect(screen.getByText(/Stale IPs/)).toBeTruthy();
  });
});
