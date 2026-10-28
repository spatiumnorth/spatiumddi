/**
 * @vitest-environment jsdom
 *
 * #2945 — the restart chip is amber only for a recent restart.
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { WorkloadHealth } from "./ClusterOverview";
import type { ClusterWorkloadHealth } from "@/lib/api";

afterEach(cleanup);

const wl = (over: Partial<ClusterWorkloadHealth>): ClusterWorkloadHealth => ({
  component: "api",
  kind: "Deployment",
  ready: 1,
  total: 1,
  restarts: 4,
  jobs_running: 0,
  status: "healthy",
  ...over,
});

describe("WorkloadHealth restart chip", () => {
  it("is amber when a restart is recent", () => {
    render(<WorkloadHealth workloads={[wl({ recent_restarts: 1 })]} />);
    const chip = screen.getByTestId("restart-chip");
    expect(chip.className).toContain("amber");
    expect(chip.textContent).toContain("4");
  });

  it("is dim, not amber, when the restarts are old", () => {
    render(<WorkloadHealth workloads={[wl({ recent_restarts: 0 })]} />);
    const chip = screen.getByTestId("restart-chip");
    expect(chip.className).not.toContain("amber");
    expect(chip.className).toContain("muted");
    expect(chip.getAttribute("title")).toContain("none in the last 15 min");
  });

  it("shows no chip at zero lifetime restarts", () => {
    render(<WorkloadHealth workloads={[wl({ restarts: 0 })]} />);
    expect(screen.queryByTestId("restart-chip")).toBeNull();
  });
});
