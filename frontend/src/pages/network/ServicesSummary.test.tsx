/**
 * @vitest-environment jsdom
 *
 * The L3VPN Summary tab shows only the attached rows the caller may read.
 * The server leaves the others out and counts them in ``withheld``; the tab
 * says how many are not shown rather than reading as "None" or "No VRF".
 */

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

import type { L3VPNSummary } from "@/lib/api";

const { L3VPNSummaryView } = await import("./ServicesPage");

afterEach(cleanup);

const FULL: L3VPNSummary = {
  kind: "mpls_l3vpn",
  vrf: {
    id: "v1",
    name: "cust-vrf",
    route_distinguisher: "65000:98",
    import_targets: ["65000:98"],
    export_targets: ["65000:99"],
  },
  edge_sites: [],
  edge_circuits: [
    {
      id: "c1",
      name: "edge-ckt",
      ckt_id: "XP-98",
      transport_class: "internet_broadband",
      bandwidth_mbps_down: 100,
      bandwidth_mbps_up: 100,
      role: null,
    },
  ],
  edge_subnets: [],
  warnings: [],
  withheld: {},
};

describe("L3VPN summary withheld sections", () => {
  it("shows the VRF and circuits when nothing is withheld", () => {
    render(<L3VPNSummaryView summary={FULL} />);
    expect(screen.getByText("cust-vrf")).toBeTruthy();
    expect(screen.getByText(/RD 65000:98/)).toBeTruthy();
    expect(screen.getByText("edge-ckt")).toBeTruthy();
    expect(screen.queryByText(/no read permission/)).toBeNull();
  });

  it("says a withheld VRF and circuit are not shown, without their values", () => {
    const { container } = render(
      <L3VPNSummaryView
        summary={{
          ...FULL,
          vrf: null,
          edge_circuits: [],
          withheld: { vrf: 1, edge_circuits: 2 },
        }}
      />,
    );
    expect(screen.getByText("Not shown (no read permission)")).toBeTruthy();
    expect(screen.getByText("2 not shown (no read permission)")).toBeTruthy();
    expect(screen.getByText("Edge circuits (2)")).toBeTruthy();
    // A withheld VRF is not reported as missing.
    expect(screen.queryByText(/No VRF attached/)).toBeNull();
    expect(container.textContent).not.toContain("65000:98");
    expect(container.textContent).not.toContain("edge-ckt");
  });

  it("treats a summary with no withheld map as fully shown", () => {
    const older: L3VPNSummary = { ...FULL };
    delete older.withheld;
    render(<L3VPNSummaryView summary={older} />);
    expect(screen.getByText("cust-vrf")).toBeTruthy();
    expect(screen.queryByText(/no read permission/)).toBeNull();
  });
});
