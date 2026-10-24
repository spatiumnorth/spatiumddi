/**
 * @vitest-environment jsdom
 *
 * The OPNsense page says when SpatiumDDI writes to a firewall (#2614), as
 * the UniFi page does (#1396): the mirror only reads, but Active block sync
 * pushes blocked IPs into an armed firewall's alias.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : name === "opnsenseApi" && method === "listRouters"
                  ? async () => []
                  : name === "authApi" && method === "myPermissions"
                    ? async () => ({ is_superadmin: true, grants: [] })
                    : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { OpnsensePage } = await import("./OpnsensePage");

afterEach(cleanup);

const NEVER_WRITES = /\bnever (?:writes?|pushes|changes)\b/i;

describe("OPNsense page: what SpatiumDDI writes", () => {
  it("does not say SpatiumDDI never writes to OPNsense, and says when it does", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <OpnsensePage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const header = await screen.findByText(/Each firewall is polled/);
    const said = (header.textContent ?? "").replace(/\s+/g, " ");
    expect(said).not.toMatch(NEVER_WRITES);
    expect(said).not.toMatch(/^Read-only integration/);
    expect(said).toMatch(/block sync/i);
    expect(said).toMatch(/writes/);
  });
});
