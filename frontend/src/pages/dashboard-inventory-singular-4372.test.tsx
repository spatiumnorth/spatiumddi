/**
 * @vitest-environment jsdom
 *
 * The Overview inventory strip names one IP space in the singular (#4372),
 * as the header line does.
 */
import { act, cleanup, render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const calls: Record<string, () => Promise<unknown>> = {};

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
            get: (_t, method) => {
              if (typeof method === "symbol") return undefined;
              if (name === "authApi" && method === "myPermissions")
                return () =>
                  Promise.resolve({ is_superadmin: true, grants: [] });
              return calls[`${name}.${String(method)}`] ?? pending;
            },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { DashboardPage } = await import("@/pages/DashboardPage");

beforeEach(() => {
  for (const k of Object.keys(calls)) delete calls[k];
});
afterEach(cleanup);

async function strip(spaces: unknown[]): Promise<string> {
  calls["ipamApi.listSpaces"] = () => Promise.resolve(spaces);
  calls["ipamApi.listSubnets"] = () => Promise.resolve([]);
  calls["dnsApi.listGroups"] = () => Promise.resolve([]);
  calls["dhcpApi.listServers"] = () => Promise.resolve([]);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 400));
  });
  const links = Array.from(document.querySelectorAll('a[href="/ipam"]'));
  return links.map((a) => a.textContent).join("|");
}

describe("inventory strip singular (#4372)", () => {
  it("says 1 space for one IP space", async () => {
    const t = await strip([{ id: "s1", name: "default" }]);
    expect(t).toContain("1space");
    expect(t).not.toContain("1spaces");
  });
  it("says 2 spaces for two", async () => {
    const t = await strip([
      { id: "s1", name: "a" },
      { id: "s2", name: "b" },
    ]);
    expect(t).toContain("2spaces");
  });
});
