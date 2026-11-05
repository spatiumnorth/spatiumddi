/**
 * @vitest-environment jsdom
 *
 * #3539 follow-ups: the heatmap legend stays in order whatever the
 * thresholds are; DHCP pool bars band at the fleet endpoint's own 80 / 95
 * (the "Pools >= 80%" / ">= 95%" cards beside them), not at Settings' IPAM
 * thresholds; and the Reports "Top subnets" bar and the UniFi subnet bar
 * follow Settings like the IPAM tree.
 */
import { cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  settings: {
    utilization_warn_threshold: 80,
    utilization_critical_threshold: 95,
  },
}));

vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ can: () => true, isLoading: false }),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pool = (id: string, percent: number) => ({
    pool_id: id,
    start_ip: `10.0.${id}.10`,
    end_ip: `10.0.${id}.20`,
    assigned: percent,
    total: 100,
    free: 100 - percent,
    percent,
    scope_name: `scope-${id}`,
    scope_is_active: true,
    subnet_network: `10.0.${id}.0/24`,
    group_id: "g",
    group_name: "grp",
  });
  return {
    ...actual,
    settingsApi: {
      ...actual.settingsApi,
      get: () => Promise.resolve({ ...h.settings }),
    },
    dhcpApi: {
      ...actual.dhcpApi,
      fleetPoolOccupancy: () =>
        Promise.resolve({
          computed_at: new Date().toISOString(),
          pool_count: 2,
          pools_warning: 0,
          pools_critical: 0,
          active_lease_count: 0,
          pools: [pool("1", 70), pool("2", 85)],
        }),
    },
    reportsApi: {
      ...actual.reportsApi,
      topSubnetsByUtilization: () =>
        Promise.resolve({
          generated_at: new Date().toISOString(),
          rows: [
            {
              id: "s1",
              name: "",
              network: "198.18.51.0/28",
              allocated_ips: 10,
              total_ips: 14,
              utilization_percent: 71.43,
            },
          ],
        }),
    },
  };
});

const { SubnetHeatmap, DhcpPoolPressure } =
  await import("@/pages/DashboardPage");
const { TopSubnetsCard } = await import("@/pages/ReportsPage");
const { UtilBar } = await import("@/pages/unifi/UnifiControllerDetailPage");

afterEach(() => {
  cleanup();
  h.settings = {
    utilization_warn_threshold: 80,
    utilization_critical_threshold: 95,
  };
});

function wrap(ui: React.ReactNode, qc = new QueryClient()) {
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const subnet = {
  id: "1",
  network: "198.18.1.0/28",
  name: "",
  total_ips: 14,
  allocated_ips: 10,
  utilization_percent: 71.43,
} as never;

/** The legend's labels, in the order they are drawn, with their swatches. */
function legend(container: HTMLElement): [string, string][] {
  const swatches = container.querySelectorAll("span.h-2\\.5.w-2\\.5");
  return Array.from(swatches).map((s) => [
    s.nextElementSibling?.textContent ?? "",
    s.className,
  ]);
}

describe("heatmap legend (#3539)", () => {
  it("drops green steps at or above a low warning line and stays ascending", async () => {
    h.settings = {
      utilization_warn_threshold: 40,
      utilization_critical_threshold: 90,
    };
    const { container, findByText } = wrap(
      <SubnetHeatmap subnets={[subnet]} />,
    );
    await findByText("90");
    const labels = legend(container).map(([l]) => l);
    expect(labels).not.toContain("50");
    expect(labels.slice(-2)).toEqual(["40", "90"]);
    const nums = labels.map((l) => parseFloat(l)).filter((n) => !isNaN(n));
    expect(nums).toEqual([...nums].sort((a, b) => a - b));
  });

  it("shows no amber swatch when warning equals critical", async () => {
    h.settings = {
      utilization_warn_threshold: 90,
      utilization_critical_threshold: 90,
    };
    const { container, findByText } = wrap(
      <SubnetHeatmap subnets={[subnet]} />,
    );
    await findByText("90");
    const swatches = legend(container);
    expect(swatches.some(([, cls]) => /amber/.test(cls))).toBe(false);
    expect(swatches.filter(([l]) => l === "90")).toHaveLength(1);
  });
});

describe("DHCP pool bars keep the pool bands (#3539)", () => {
  it("bands at 80 / 95 whatever Settings' IPAM thresholds are", async () => {
    h.settings = {
      utilization_warn_threshold: 60,
      utilization_critical_threshold: 70,
    };
    const qc = new QueryClient();
    const { container, findByText } = wrap(<DhcpPoolPressure dhcpOn />, qc);
    await findByText("10.0.2.10–10.0.2.20");
    // Let the settings query land too, so a bar following Settings would
    // have recoloured by now.
    await waitFor(() =>
      expect(qc.getQueryState(["settings"])?.status).toBe("success"),
    );
    const fills = Array.from(
      container.querySelectorAll("a .h-full.rounded-full"),
    ).map((e) => e.className);
    expect(fills).toHaveLength(2);
    expect(fills[0]).toMatch(/emerald/);
    expect(fills[1]).toMatch(/amber/);
  });
});

describe("other subnet utilization bars follow Settings (#3539)", () => {
  it("Reports' Top subnets draws 71% green at 80 / 95", async () => {
    const { container, findByText } = wrap(<TopSubnetsCard />);
    await findByText("71.4%");
    await waitFor(() => {
      const fill = container.querySelector(".h-full.rounded-full");
      expect(fill?.className).toMatch(/green|emerald/);
      expect(fill?.className).not.toMatch(/amber/);
    });
  });

  it("Reports' Top subnets draws 71% red at 50 / 70", async () => {
    h.settings = {
      utilization_warn_threshold: 50,
      utilization_critical_threshold: 70,
    };
    const { container, findByText } = wrap(<TopSubnetsCard />);
    await findByText("71.4%");
    await waitFor(() =>
      expect(
        container.querySelector(".h-full.rounded-full")?.className,
      ).toMatch(/bg-red-500/),
    );
  });

  it("the UniFi subnet bar draws 85% red at 50 / 80", async () => {
    h.settings = {
      utilization_warn_threshold: 50,
      utilization_critical_threshold: 80,
    };
    const { container } = wrap(<UtilBar percent={85} />);
    await waitFor(() =>
      expect(
        container.querySelector(".h-1\\.5.rounded-full.bg-red-500"),
      ).not.toBeNull(),
    );
  });
});
