/**
 * @vitest-environment jsdom
 *
 * The Dashboard's heatmap and utilization bars band at Settings' Warning /
 * Critical Threshold, not fixed 70/85/95 (#3539).
 */
import { cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    settingsApi: {
      ...actual.settingsApi,
      get: () =>
        Promise.resolve({
          utilization_warn_threshold: 80,
          utilization_critical_threshold: 95,
        }),
    },
  };
});

const { SubnetHeatmap, UtilizationBar } = await import("@/pages/DashboardPage");

afterEach(cleanup);

const subnet = (id: string, pct: number) =>
  ({
    id,
    network: `198.18.${id}.0/28`,
    name: "",
    total_ips: 14,
    allocated_ips: 10,
    utilization_percent: pct,
  }) as never;

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Dashboard utilization bands follow Settings (#3539)", () => {
  it("draws 71% green and 90% amber on the heatmap, with a matching legend", async () => {
    const { container, findByText } = wrap(
      <SubnetHeatmap subnets={[subnet("1", 71.43), subnet("2", 90)]} />,
    );
    await findByText("95");
    const cells = container.querySelectorAll("a");
    expect(cells[0].className).not.toMatch(/amber|red/);
    expect(cells[1].className).toMatch(/bg-amber-400/);
    expect(container.textContent).toContain("80");
    expect(container.textContent).not.toContain("85");
  });

  it("counts HOT at the critical threshold, not 85", async () => {
    const { findByText, container } = wrap(
      <SubnetHeatmap subnets={[subnet("1", 90), subnet("2", 96)]} />,
    );
    await findByText("95");
    await waitFor(() => {
      const hot = Array.from(container.querySelectorAll("span")).find(
        (e) => e.textContent === "HOT",
      );
      expect(hot?.nextElementSibling?.textContent).toBe("1");
    });
  });

  it("colours the bar by the same bands", async () => {
    const { container } = wrap(<UtilizationBar percent={71.43} />);
    await waitFor(() =>
      expect(container.querySelector(".h-full")?.className).toMatch(/emerald/),
    );
  });
});
