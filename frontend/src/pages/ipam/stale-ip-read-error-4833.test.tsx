/**
 * @vitest-environment jsdom
 *
 * #4833: a failed stale-IP report read must not render the healthy
 * empty-state sentence.
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
      getStaleIPs: () => Promise.reject(new Error("boom")),
    },
  };
});

const { StaleIPReportPage } = await import("./StaleIPReportPage");

afterEach(cleanup);

describe("StaleIPReportPage read error (#4833)", () => {
  it("does not say the address space is healthy when the read failed", async () => {
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <MemoryRouter>
          <StaleIPReportPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await screen
      .findByText(/stale IPs/i, {}, { timeout: 3000 })
      .catch(() => {});
    await new Promise((r) => setTimeout(r, 200));
    expect(document.body.textContent).not.toMatch(/looks healthy/);
    expect(document.body.textContent).toMatch(/stale IPs/);
  });
});
