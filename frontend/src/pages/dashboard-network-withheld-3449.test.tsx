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

const summary = (
  withheld: Record<string, boolean>,
  extra: Record<string, unknown> = {},
) => ({
  generated_at: "2026-11-03T00:00:00Z",
  withheld,
  asn_drift_count: 0,
  rpki_expiring_count: 0,
  rpki_expired_count: 0,
  rpki_total_count: 0,
  rpki_last_checked_at: null,
  rpki_expiry_known_count: 0,
  circuit_term_expiring_count: 0,
  circuit_status_changed_count: 0,
  service_orphan_count: 0,
  overlay_impacted_count: 0,
  asn_drift: [],
  rpki_expiring: [],
  circuit_alerts: [],
  orphan_services: [],
  overlay_impact: [],
  ...extra,
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
    // The server zeroes the total for a withheld grant: the tile must not
    // then claim nothing was pulled (#3540).
    expect(kpi("RPKI expired")).not.toContain("no ROAs tracked");
    const expiredLink = Array.from(document.querySelectorAll("p"))
      .find((e) => e.textContent === "RPKI expired")
      ?.closest("a");
    expect(expiredLink?.getAttribute("title") ?? "").not.toContain(
      "have been pulled",
    );
    expect(text).not.toContain("No RPKI ROAs are tracked yet.");
  });

  it("the combined card names the withheld half when the other has rows", async () => {
    // The reported role: services readable, overlays not. A list of orphan
    // services must not read as "and no overlay impact".
    calls["dashboardsApi.networkSummary"] = () =>
      Promise.resolve(
        summary(
          { overlay: true },
          {
            service_orphan_count: 1,
            orphan_services: [
              {
                service_id: "s1",
                service_name: "svc-one",
                resource_kind: "vrf",
                resource_id: "r1",
              },
            ],
          },
        ),
      );
    const text = await show();
    expect(text).toContain("svc-one");
    expect(text).toContain("Overlay impact is not visible to your role.");
    expect(text).not.toContain("no overlays touching down circuits");
  });

  it("the combined card's empty readable half says only what it knows", async () => {
    calls["dashboardsApi.networkSummary"] = () =>
      Promise.resolve(summary({ service: true }));
    const text = await show();
    expect(text).toContain("No overlays touching down circuits.");
    expect(text).toContain("Orphan services are not visible to your role.");
    expect(text).not.toContain("Service catalog clean");
  });

  it("with no ROAs tracked the expired tile and panel are not an all-clear (#3540)", async () => {
    calls["dashboardsApi.networkSummary"] = () => Promise.resolve(summary({}));
    const text = await show();
    expect(kpi("RPKI expired")).toContain("—");
    expect(kpi("RPKI expired")).toContain("no ROAs tracked");
    expect(text).not.toContain("No ROAs are expiring");
    expect(text).toContain("No RPKI ROAs are tracked yet.");
  });

  it("with ROAs tracked a zero expired count is still good (#3540)", async () => {
    calls["dashboardsApi.networkSummary"] = () =>
      Promise.resolve(
        summary(
          {},
          {
            rpki_total_count: 5,
            // a source that ships lifetimes (#3557), so expiry is measured
            rpki_expiry_known_count: 5,
            rpki_last_checked_at: new Date().toISOString(),
          },
        ),
      );
    const text = await show();
    expect(kpi("RPKI expired")).not.toContain("no ROAs tracked");
    expect(text).toContain("No ROAs are expiring");
  });

  it("a summary without a ROA total is not read as none tracked (#3540)", async () => {
    calls["dashboardsApi.networkSummary"] = () =>
      Promise.resolve(summary({}, { rpki_total_count: undefined }));
    const text = await show();
    expect(kpi("RPKI expired")).not.toContain("no ROAs tracked");
    expect(text).not.toContain("No RPKI ROAs are tracked yet.");
  });

  it("nothing withheld keeps the all-clear wording", async () => {
    calls["dashboardsApi.networkSummary"] = () => Promise.resolve(summary({}));
    const text = await show();
    expect(text).not.toContain("not visible to your role");
    expect(text).toContain("No circuits past term");
  });
});

describe("RPKI expiry with no ROA lifetimes (#3557)", () => {
  const tracked = {
    rpki_total_count: 13,
    rpki_last_checked_at: new Date().toISOString(),
  };

  it("a source with no per-ROA lifetime is not measured, not a green zero", async () => {
    calls["dashboardsApi.networkSummary"] = () =>
      Promise.resolve(summary({}, { ...tracked, rpki_expiry_known_count: 0 }));
    const text = await show();
    for (const l of ["RPKI expiring", "RPKI expired"]) {
      expect(kpi(l)).toContain("n/a");
      expect(kpi(l)).toContain("source has no ROA lifetimes");
    }
    expect(text).not.toContain("No ROAs are expiring");
    expect(text).toContain("Not measured");
  });

  it("known lifetimes keep the counts and the all-clear", async () => {
    calls["dashboardsApi.networkSummary"] = () =>
      Promise.resolve(summary({}, { ...tracked, rpki_expiry_known_count: 13 }));
    const text = await show();
    expect(kpi("RPKI expiring")).toContain("0");
    expect(kpi("RPKI expired")).not.toContain("n/a");
    expect(text).toContain("No ROAs are expiring");
  });
});
