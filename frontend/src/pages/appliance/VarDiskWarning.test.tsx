/**
 * @vitest-environment jsdom
 *
 * #2400 — the /var warning on the Fleet drilldown and the Cluster node card.
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { VarDiskWarning } from "./VarDiskWarning";

afterEach(cleanup);

describe("VarDiskWarning", () => {
  it("renders nothing without a finding", () => {
    const { container } = render(<VarDiskWarning finding={null} />);
    expect(container.innerHTML).toBe("");
  });

  it("names a critical finding with the free share and the server's detail", () => {
    render(
      <VarDiskWarning
        finding={{
          severity: "critical",
          free_pct: 12.7,
          detail: "1946 MiB of 15360 MiB free on /var (13%).",
        }}
      />,
    );
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("Disk space critical · 12% free");
    expect(alert.textContent).toContain("1946 MiB of 15360 MiB free on /var");
    expect(alert.className).toContain("rose");
  });

  it("marks a warning amber", () => {
    render(
      <VarDiskWarning
        finding={{ severity: "warning", free_pct: 18, detail: "low" }}
      />,
    );
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("Disk space low");
    expect(alert.className).toContain("amber");
  });

  it("does not invent a percentage under DiskPressure with no reading", () => {
    render(
      <VarDiskWarning
        finding={{
          severity: "critical",
          free_pct: null,
          detail: "The kubelet reports DiskPressure",
        }}
      />,
    );
    expect(screen.getByRole("alert").textContent).not.toContain("% free");
  });
});
