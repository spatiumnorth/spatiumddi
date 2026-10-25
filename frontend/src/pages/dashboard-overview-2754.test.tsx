/**
 * @vitest-environment jsdom
 *
 * The Dashboard asks for the audit log and the certificate list only when
 * the user may read them, and says so in the card when it may not, instead
 * of "No recent activity" / "0 of 0 monitored" (#2702).
 */
import { act, cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const calls: Record<string, () => Promise<unknown>> = {};
let grants: unknown[] = [];

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
                return () => Promise.resolve({ is_superadmin: false, grants });
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

const refused = () =>
  Promise.reject({
    response: { status: 403, data: { detail: "Permission denied" } },
  });

beforeEach(() => {
  for (const k of Object.keys(calls)) delete calls[k];
  grants = [];
});
afterEach(cleanup);

async function show() {
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
}

const kpi = (label: string) => {
  const p = Array.from(document.querySelectorAll("p")).find(
    (e) => e.textContent === label,
  );
  return p?.parentElement?.parentElement as HTMLElement;
};

describe("Overview with refused reads (#2754)", () => {
  it("does not present refused reads as zero and healthy", async () => {
    calls["ipamApi.listSpaces"] = refused;
    calls["ipamApi.listSubnets"] = refused;
    calls["dnsApi.listGroups"] = refused;
    calls["dhcpApi.listServers"] = refused;
    await show();
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/0 subnets/);
    expect(text).not.toMatch(/0 spaces/);
    expect(text).not.toContain("healthy");
    expect(text).toContain("status unknown");
    expect(text).not.toContain("No subnets yet");
    expect(kpi("Agents needing attention").textContent).toContain("—");
    expect(kpi("Capacity pressure").textContent).toContain("—");
  });

  it("still says healthy when the reads succeeded and are empty", async () => {
    calls["ipamApi.listSpaces"] = () => Promise.resolve([]);
    calls["ipamApi.listSubnets"] = () => Promise.resolve([]);
    calls["dnsApi.listGroups"] = () => Promise.resolve([]);
    calls["dhcpApi.listServers"] = () => Promise.resolve([]);
    await show();
    expect(document.body.textContent).toContain("healthy");
    expect(document.body.textContent).toContain("0 subnets");
  });
});

describe("Agents needing attention: tile and panel agree (#2755)", () => {
  const server = (over: Record<string, unknown>) => ({
    id: "s1",
    name: "ns1",
    host: "10.0.0.1",
    driver: "bind9",
    status: "active",
    is_enabled: true,
    maintenance_mode: false,
    group_id: "g1",
    config_apply_status: null,
    config_apply_error: null,
    daemon_status: null,
    daemon_not_serving: false,
    ...over,
  });
  const drive = async (over: Record<string, unknown>) => {
    calls["ipamApi.listSpaces"] = () => Promise.resolve([]);
    calls["ipamApi.listSubnets"] = () => Promise.resolve([]);
    calls["dhcpApi.listServers"] = () => Promise.resolve([]);
    calls["dnsApi.listGroups"] = () =>
      Promise.resolve([{ id: "g1", name: "grp" }]);
    calls["dnsApi.listServers"] = () => Promise.resolve([server(over)]);
    await show();
    await waitFor(() =>
      expect(document.body.textContent).toContain("Agents needing attention ("),
    );
  };

  it("counts a daemon that is not serving on the tile", async () => {
    await drive({ daemon_status: "degraded", daemon_not_serving: true });
    const text = document.body.textContent ?? "";
    console.log("DBG", text.slice(0, 1500));
    expect(text).toContain("Agents needing attention (1)");
    const tile = kpi("Agents needing attention");
    expect(tile.querySelector("p.text-2xl")?.textContent).toBe("1");
    expect(tile.textContent).not.toContain("1 healthy");
  });

  it("counts an agent whose zones were refused, and the header notices", async () => {
    await drive({
      config_apply_status: "reverted",
      config_apply_error:
        "partial apply: zone x.example. refused by the daemon",
    });
    const tile = kpi("Agents needing attention");
    expect(document.body.textContent).toContain("Agents needing attention (1)");
    expect(tile.querySelector("p.text-2xl")?.textContent).toBe("1");
    expect(document.body.textContent).toContain("degraded");
    expect(document.body.textContent).not.toContain("healthy");
  });
});
