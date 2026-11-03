/**
 * @vitest-environment jsdom
 *
 * A Network panel the server withheld is told as "not visible to your
 * role", never as a green zero / all-clear (#3449).
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
                  Promise.resolve({ is_superadmin: false, grants: [] });
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

const summary = (withheld: Record<string, boolean>) => ({
  generated_at: "2026-11-03T00:00:00Z",
  withheld,
  asn_drift_count: 0,
  rpki_expiring_count: 0,
  rpki_expired_count: 0,
  rpki_total_count: 0,
  rpki_last_checked_at: null,
  circuit_term_expiring_count: 0,
  circuit_status_changed_count: 0,
  service_orphan_count: 0,
  overlay_impacted_count: 0,
  asn_drift: [],
  rpki_expiring: [],
  circuit_alerts: [],
  orphan_services: [],
  overlay_impact: [],
});

beforeEach(() => {
  for (const k of Object.keys(calls)) delete calls[k];
  localStorage.clear();
});
afterEach(cleanup);

async function show() {
  localStorage.setItem("dashboard-tab", "network");
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

function kpi(label: string) {
  const el = Array.from(document.querySelectorAll("p")).find(
    (e) => e.textContent === label,
  );
  return el?.closest("a")?.textContent ?? "";
}

describe("withheld Network panels (#3449)", () => {
  it("a withheld circuit panel is not a green zero or an all-clear", async () => {
    calls["dashboardsApi.networkSummary"] = () =>
      Promise.resolve(summary({ circuit: true }));
    const text = await show();
    expect(kpi("Circuit alerts")).toContain("—");
    expect(kpi("Circuit alerts")).toContain("not visible to your role");
    expect(kpi("Circuit alerts")).not.toContain("0 term");
    expect(text).not.toContain("No circuits past term");
    // A readable panel still says its honest zero.
    expect(kpi("ASN drift")).toContain("0");
    expect(text).toContain("No ASNs in drift state right now.");
  });

  it("a withheld ASN grant covers the drift and both RPKI KPIs", async () => {
    calls["dashboardsApi.networkSummary"] = () =>
      Promise.resolve(summary({ asn: true }));
    const text = await show();
    for (const l of ["ASN drift", "RPKI expiring", "RPKI expired"]) {
      expect(kpi(l)).toContain("not visible to your role");
    }
    expect(text).not.toContain("No ASNs in drift state");
    expect(text).not.toContain("No ROAs are expiring");
  });

  it("nothing withheld keeps the all-clear wording", async () => {
    calls["dashboardsApi.networkSummary"] = () => Promise.resolve(summary({}));
    const text = await show();
    expect(text).not.toContain("not visible to your role");
    expect(text).toContain("No circuits past term");
  });
});
