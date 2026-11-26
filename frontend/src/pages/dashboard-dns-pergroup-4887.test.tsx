/**
 * @vitest-environment jsdom
 *
 * The Overview's DNS tab and zone counts do not draw failed per-group
 * server / zone reads as "none" (#4887).
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
              const k = `${name}.${String(method)}`;
              if (calls[k]) return calls[k];
              return pending;
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
  localStorage.clear();
});
afterEach(cleanup);

const boom = () => Promise.reject(new Error("Network Error"));

async function draw(tab: string) {
  calls["dnsApi.listGroups"] = () =>
    Promise.resolve([{ id: "g1", name: "default" }]);
  calls["dnsApi.listServers"] = boom;
  calls["dnsApi.listZones"] = boom;
  localStorage.setItem("dashboard-tab", tab);
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
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
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
  return document.body.textContent ?? "";
}

describe("failed per-group DNS reads (#4887)", () => {
  it("DNS tab does not say no server is registered or 0 zones", async () => {
    const text = await draw("dns");
    expect(text).not.toContain("No DNS servers registered");
    expect(text).toContain("DNS servers");
    expect(text).not.toMatch(/DNS Zones\s*0/);
  });

  it("Overview strip does not count 0 DNS zones", async () => {
    const text = await draw("overview");
    expect(text).not.toMatch(/0\s*DNS zones/);
  });
});
