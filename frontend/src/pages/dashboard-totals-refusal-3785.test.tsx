/**
 * @vitest-environment jsdom
 *
 * #3785: the IPv4 totals count every subnet, /30 included. #3796: the
 * ASNs / VRFs / Domains cards say a refusal, not "Failed to load".
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
  try {
    localStorage.clear();
  } catch {
    /* jsdom without storage */
  }
});
afterEach(cleanup);

async function show(tab: string) {
  localStorage.setItem("dashboard-tab", tab);
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
  return document.body.textContent ?? "";
}

const sub = (id: string, network: string, total: number, alloc: number) => ({
  id,
  network,
  name: id,
  total_ips: total,
  allocated_ips: alloc,
  utilization_percent: (alloc / total) * 100,
  space_id: "sp",
  block_id: "b",
});

describe("Dashboard IPv4 totals (#3785)", () => {
  it("count a /30's addresses", async () => {
    calls["ipamApi.listSubnets"] = () =>
      Promise.resolve([
        sub("a", "10.0.0.0/29", 8, 3),
        sub("b", "10.0.1.0/30", 4, 2),
      ]);
    const text = await show("ipam");
    expect(text).toContain("5 / 12");
  });
});

describe("refused ASN / VRF / Domain cards (#3796)", () => {
  it("say the refusal, not Failed to load", async () => {
    const refused = () =>
      Promise.reject({
        response: { status: 403, data: { detail: "Forbidden" } },
      });
    calls["asnsApi.list"] = refused;
    calls["vrfsApi.list"] = refused;
    calls["domainsApi.list"] = refused;
    const text = await show("overview");
    expect(text).not.toContain("Failed to load ASN data");
    expect(text).not.toContain("Failed to load VRF data");
    expect(text).not.toContain("Failed to load domain data");
    expect(text).toContain("You don't have permission to see ASNs");
    expect(text).toContain("You don't have permission to see VRFs");
    expect(text).toContain("You don't have permission to see domains");
  });
});
