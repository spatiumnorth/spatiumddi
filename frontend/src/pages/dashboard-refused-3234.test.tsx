/**
 * @vitest-environment jsdom
 *
 * A Dashboard read the server refused is told as refused, never counted as
 * zero or "none" (#3234); a Security list the summary withheld is told as
 * withheld, never as the all-clear (#3235).
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

const refused = () =>
  Promise.reject({
    response: { status: 403, data: { detail: "Forbidden" } },
  });

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

function refuseEstate() {
  calls["ipamApi.listSpaces"] = refused;
  calls["ipamApi.listSubnets"] = refused;
  calls["dnsApi.listGroups"] = refused;
  calls["dhcpApi.listServers"] = refused;
  calls["dhcpApi.listGroups"] = refused;
}

describe("refused reads are not an empty estate (#3234)", () => {
  it("Overview: Top Subnets says the read was refused", async () => {
    refuseEstate();
    const text = await show("overview");
    expect(text).not.toContain("No subnets have allocated IPs yet.");
    expect(text).not.toMatch(/Showing 0 of 0/);
    expect(text).toContain("You don't have permission to see subnets");
  });

  it("IPAM tab: strip, split, headroom and table say refused", async () => {
    refuseEstate();
    const text = await show("ipam");
    expect(text).not.toContain("No subnets have allocated IPs yet.");
    expect(text).not.toMatch(/Showing 0 of 0/);
    expect(text).not.toContain("0 healthy");
    expect(text).not.toContain("0 free");
    expect(text).not.toContain("0.0%");
    expect(text).not.toContain("100.0%");
    expect(text).not.toMatch(/0 subnets/);
    expect(text).not.toContain("none registered");
    expect(text).not.toContain("no groups");
  });

  it("DNS and DHCP tabs say refused, not 'registered none'", async () => {
    refuseEstate();
    const dns = await show("dns");
    expect(dns).not.toContain("No DNS servers registered");
    expect(dns).toContain("You don't have permission to see DNS servers");
    cleanup();
    const dhcp = await show("dhcp");
    expect(dhcp).not.toContain("No DHCP servers registered");
    expect(dhcp).toContain("You don't have permission to see DHCP servers");
  });

  it("Compliance tab does not say 0% of 0 subnets", async () => {
    refuseEstate();
    const text = await show("compliance");
    expect(text).not.toContain("of 0 subnets");
    expect(text).toContain("you may not read subnets");
  });

  it("a 5xx says unavailable, not permission", async () => {
    calls["ipamApi.listSpaces"] = () => Promise.resolve([]);
    calls["ipamApi.listSubnets"] = () =>
      Promise.reject({ response: { status: 500, data: { detail: "boom" } } });
    const text = await show("overview");
    expect(text).toContain("Couldn't load subnets");
    expect(text).not.toContain("permission to see subnets");
  });

  it("still says 'none' when the read succeeded and is empty", async () => {
    calls["ipamApi.listSpaces"] = () => Promise.resolve([]);
    calls["ipamApi.listSubnets"] = () => Promise.resolve([]);
    const text = await show("overview");
    expect(text).toContain("No subnets have allocated IPs yet.");
  });
});

const summary = (over: Record<string, unknown>) => ({
  generated_at: "2026-11-01T00:00:00Z",
  mfa_total_local_users: 5,
  mfa_enrolled_count: 0,
  mfa_coverage_pct: 0,
  mfa_unenrolled: [],
  api_tokens_total: 0,
  api_tokens_expiring_count: 0,
  api_tokens_expiring: [],
  failed_login_window_hours: 24,
  failed_login_total: 4,
  failed_login_top_sources: [],
  permission_change_window_days: 7,
  permission_change_count: 541,
  permission_changes: [],
  ...over,
});

describe("Security tab lists the summary withheld (#3235)", () => {
  it("says withheld, never the all-clear sentences", async () => {
    calls["dashboardsApi.securitySummary"] = () =>
      Promise.resolve(summary({ detail_withheld: true }));
    const text = await show("security");
    expect(text).not.toContain("Every local user has TOTP enrolled.");
    expect(text).not.toContain("No failed logins in the last");
    expect(text).not.toContain("No role / group / token");
    expect(text).not.toContain("No tokens are expiring");
    expect(text).toContain("not shown to your role");
    expect(text).toContain("541");
  });

  it("keeps the all-clear sentences when nothing was withheld", async () => {
    calls["dashboardsApi.securitySummary"] = () =>
      Promise.resolve(
        summary({
          detail_withheld: false,
          mfa_total_local_users: 0,
          failed_login_total: 0,
          permission_change_count: 0,
        }),
      );
    const text = await show("security");
    expect(text).toContain("Every local user has TOTP enrolled.");
    expect(text).toContain("No failed logins in the last 24 h.");
  });
});
