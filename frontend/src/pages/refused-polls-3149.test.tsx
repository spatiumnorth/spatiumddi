/**
 * @vitest-environment jsdom
 *
 * A read the server refused (403) is not asked again on a timer: the
 * Dashboard's integration lists, Looking Glass card, Integrations and
 * Conformity tabs, Packet Capture's list and the Looking Glass sessions and
 * peers each ask once, since every refusal writes a `denied` audit row
 * (#3149).
 */
import { act, cleanup, render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const calls = new Map<string, number>();

const denied = () =>
  Promise.reject({
    response: { status: 403, data: { detail: "Permission denied" } },
  });

const SETTINGS = {
  integration_kubernetes_enabled: true,
  integration_docker_enabled: true,
  integration_proxmox_enabled: true,
  integration_opnsense_enabled: true,
  integration_panos_enabled: true,
  integration_fortinet_enabled: true,
  integration_meraki_enabled: true,
  integration_cloud_enabled: true,
  integration_unifi_enabled: true,
};

const REFUSED = new Set([
  "kubernetesApi.listClusters",
  "dockerApi.listHosts",
  "proxmoxApi.listNodes",
  "opnsenseApi.listRouters",
  "panosApi.list",
  "fortinetApi.list",
  "merakiApi.list",
  "cloudApi.listEndpoints",
  "unifiApi.listControllers",
  "lookingGlassApi.getDashboardSummary",
  "lookingGlassApi.listSessions",
  "lookingGlassApi.listPeers",
  "dashboardsApi.integrationsSummary",
  "conformityApi.summary",
  "conformityApi.listResults",
  "pcapApi.listCaptures",
]);

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
              const k = `${name}.${String(method)}`;
              return () => {
                calls.set(k, (calls.get(k) ?? 0) + 1);
                if (k === "authApi.myPermissions")
                  return Promise.resolve({ is_superadmin: false, grants: [] });
                if (k === "settingsApi.get") return Promise.resolve(SETTINGS);
                return REFUSED.has(k) ? denied() : pending();
              };
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
const { PacketCapturePage } = await import("@/pages/pcap/PacketCapturePage");
const { SessionsTab } =
  await import("@/pages/network/looking-glass/SessionsTab");

beforeEach(() => {
  calls.clear();
  localStorage.clear();
  vi.useFakeTimers();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

async function held(ui: React.ReactElement, ms: number) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

function expectAskedOnce(keys: string[]) {
  for (const k of keys) {
    expect(calls.get(k), k).toBe(1);
  }
}

describe("refused reads are not polled (#3149)", () => {
  it("Dashboard Overview: nine integration lists and the Looking Glass card", async () => {
    await held(<DashboardPage />, 95_000);
    expectAskedOnce([
      "kubernetesApi.listClusters",
      "dockerApi.listHosts",
      "proxmoxApi.listNodes",
      "opnsenseApi.listRouters",
      "panosApi.list",
      "fortinetApi.list",
      "merakiApi.list",
      "cloudApi.listEndpoints",
      "unifiApi.listControllers",
      "lookingGlassApi.getDashboardSummary",
    ]);
  });

  it("Dashboard Integrations tab", async () => {
    localStorage.setItem("dashboard-tab", "integrations");
    await held(<DashboardPage />, 95_000);
    expectAskedOnce(["dashboardsApi.integrationsSummary"]);
  });

  it("Dashboard Conformity tab", async () => {
    localStorage.setItem("dashboard-tab", "conformity");
    await held(<DashboardPage />, 190_000);
    expectAskedOnce(["conformityApi.summary", "conformityApi.listResults"]);
  });

  it("Packet Capture says the list was refused and asks once", async () => {
    await held(<PacketCapturePage />, 30_000);
    expectAskedOnce(["pcapApi.listCaptures"]);
    const text = document.body.textContent ?? "";
    expect(text).toContain("You don't have permission to see packet captures");
    expect(text).not.toContain("Failed to load captures");
  });

  it("Looking Glass sessions and peers", async () => {
    await held(
      <SessionsTab collectors={[]} onEdit={() => {}} onViewRoutes={() => {}} />,
      95_000,
    );
    expectAskedOnce([
      "lookingGlassApi.listSessions",
      "lookingGlassApi.listPeers",
    ]);
  });
});
