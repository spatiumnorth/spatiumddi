/**
 * @vitest-environment jsdom
 *
 * #4853: a refused NAT read in the per-IP dialog must not say the IP has
 * no NAT mappings.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    natApi: {
      ...actual.natApi,
      byIp: () =>
        Promise.reject({
          response: { status: 403, data: { detail: "Forbidden" } },
        }),
    },
  };
});

const { NatMappingsForIpModal } = await import("./IPAMPage");

afterEach(cleanup);

describe("NatMappingsForIpModal refused read (#4853)", () => {
  it("says the reader may not see NAT mappings, not that there are none", async () => {
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <MemoryRouter>
          <NatMappingsForIpModal
            ip={{ id: "ip1", address: "10.0.0.5" } as never}
            onClose={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await screen.findByText(/You don't have permission to see/);
    expect(document.body.textContent).toContain("this IP's NAT mappings");
    expect(document.body.textContent).not.toMatch(/No NAT mappings reference/);
  });
});
