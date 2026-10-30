/**
 * @vitest-environment jsdom
 *
 * #3105 / #3106 / #3107 — a read-only Viewer on the Appliance page.
 *
 * The MetalLB card is not offered to a user who may not read or change it;
 * a read the server refused (403) is not asked again on a timer; and a
 * refusal reads as a refusal, never as "nothing there".
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

let superadmin = false;

function forbidden(detail = "Permission denied: need 'admin' on 'appliance'") {
  return Object.assign(new Error("Request failed with status code 403"), {
    status: 403,
    response: { status: 403, data: { detail } },
  });
}

const getMetalLBConfig = vi.fn();
const listAppliances = vi.fn();
const listEtcdSnapshots = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    applianceApprovalApi: {
      ...actual.applianceApprovalApi,
      getMetalLBConfig,
      list: listAppliances,
      listEtcdSnapshots,
    },
    applianceSystemApi: {
      ...actual.applianceSystemApi,
      info: () => new Promise(() => {}),
    },
    authApi: {
      ...actual.authApi,
      me: () => Promise.resolve({ is_superadmin: superadmin }),
    },
    settingsApi: {
      ...actual.settingsApi,
      get: () => Promise.resolve({ console_mode: "dashboard" }),
    },
    firewallApi: {
      ...actual.firewallApi,
      getEnforcement: () => Promise.resolve({ logging_enabled: false }),
    },
  };
});

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => superadmin,
      isSuperadmin: superadmin,
      isLoading: false,
    }),
  };
});

vi.mock("@/pages/appliance/ClusterOverview", () => ({
  ClusterOverview: () => null,
}));
vi.mock("@/pages/appliance/ContainersTab", () => ({
  ContainersTab: () => null,
}));

const { NetworkTab } = await import("@/pages/appliance/NetworkTab");
const { ClusterTab } = await import("@/pages/appliance/ClusterTab");
const { FirewallLogsSection } = await import("@/pages/appliance/FirewallTab");
const { shouldRetry } = await import("@/lib/queryClient");

function wrap(node: ReactNode) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: shouldRetry, retryDelay: 1 } },
  });
  return render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

beforeEach(() => {
  superadmin = false;
  sessionStorage.clear();
  getMetalLBConfig.mockReset();
  listAppliances.mockReset();
  listEtcdSnapshots.mockReset();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

async function tick(ms: number) {
  await vi.advanceTimersByTimeAsync(ms);
}

describe("#3105 MetalLB card", () => {
  it("offers a Viewer no form and does not read the settings", async () => {
    getMetalLBConfig.mockRejectedValue(forbidden());
    wrap(<NetworkTab />);
    expect(
      await screen.findByText(/Viewing or changing the control-plane VIP/),
    ).toBeTruthy();
    expect(screen.queryByText(/Enable MetalLB/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Save" })).toBeNull();
    expect(getMetalLBConfig).not.toHaveBeenCalled();
  });

  it("leaves the form to a superadmin", async () => {
    superadmin = true;
    getMetalLBConfig.mockResolvedValue({
      enabled: false,
      pool_addresses: [],
      control_plane_vip: "",
    });
    wrap(<NetworkTab />);
    expect(await screen.findByText(/Enable MetalLB/)).toBeTruthy();
    expect(getMetalLBConfig).toHaveBeenCalled();
  });
});

describe("#3106 refused reads are not polled", () => {
  it("stops asking for MetalLB settings after a 403", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    superadmin = true;
    getMetalLBConfig.mockRejectedValue(forbidden());
    wrap(<NetworkTab />);
    await tick(100);
    expect(getMetalLBConfig).toHaveBeenCalledTimes(1);
    await tick(35_000);
    expect(getMetalLBConfig).toHaveBeenCalledTimes(1);
  });

  it("still polls MetalLB settings while they answer", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    superadmin = true;
    getMetalLBConfig.mockResolvedValue({ enabled: false, pool_addresses: [] });
    wrap(<NetworkTab />);
    await tick(100);
    await tick(21_000);
    expect(getMetalLBConfig.mock.calls.length).toBeGreaterThan(1);
  });

  it("stops asking for the appliance list after a 403", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    listAppliances.mockRejectedValue(forbidden());
    wrap(<FirewallLogsSection />);
    await tick(100);
    expect(listAppliances).toHaveBeenCalledTimes(1);
    await tick(95_000);
    expect(listAppliances).toHaveBeenCalledTimes(1);
  });
});

describe("#3107 a refusal is not an empty state", () => {
  it("says the etcd snapshots were refused", async () => {
    sessionStorage.setItem("appliance.cluster.section", JSON.stringify("etcd"));
    listEtcdSnapshots.mockRejectedValue(forbidden());
    wrap(<ClusterTab initialSection="etcd" />);
    expect(
      await screen.findByText(
        /don't have permission to see the etcd snapshots/,
      ),
    ).toBeTruthy();
    expect(screen.queryByText(/No recoverable etcd snapshots yet/)).toBeNull();
  });

  it("still says there are none when the read succeeded empty", async () => {
    listEtcdSnapshots.mockResolvedValue({ available: false, snapshots: [] });
    wrap(<ClusterTab initialSection="etcd" />);
    expect(
      await screen.findByText(/No recoverable etcd snapshots yet/),
    ).toBeTruthy();
  });

  it("does not call a refused appliance list 'No online appliances'", async () => {
    listAppliances.mockRejectedValue(forbidden());
    wrap(<FirewallLogsSection />);
    expect(
      await screen.findByText(
        /don't have permission to see the appliance list/,
      ),
    ).toBeTruthy();
    expect(screen.queryByText("No online appliances")).toBeNull();
  });

  it("keeps 'No online appliances' for a list that is really empty", async () => {
    listAppliances.mockResolvedValue([]);
    wrap(<FirewallLogsSection />);
    expect(await screen.findByText("No online appliances")).toBeTruthy();
  });
});
