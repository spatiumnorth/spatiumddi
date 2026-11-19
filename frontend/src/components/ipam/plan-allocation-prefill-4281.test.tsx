/**
 * @vitest-environment jsdom
 *
 * Plan allocation pre-fills no IPv6 subnet size longer than /64 (#4281): a /60
 * block used to open on /68, a size SLAAC cannot use.
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { IPBlock } from "@/lib/api";
import { PlanAllocationModal } from "./PlanAllocationModal";
import { defaultPlanPrefix } from "@/lib/plan-allocation";

afterEach(cleanup);

function prefixField(network: string): HTMLInputElement {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <PlanAllocationModal block={{ network } as IPBlock} onClose={() => {}} />
    </QueryClientProvider>,
  );
  return screen.getAllByRole("spinbutton")[1] as HTMLInputElement;
}

describe("Plan allocation pre-fill", () => {
  it("opens an IPv6 /60 block on /64, not /68", () => {
    expect(prefixField("fd5e:1118:0:10::/60").value).toBe("64");
  });

  it("opens an IPv6 /48 block on /64, not /56", () => {
    expect(prefixField("fd5e:1117::/48").value).toBe("64");
  });

  it("leaves the field empty on an IPv6 block already at /64", () => {
    expect(defaultPlanPrefix(true, 64)).toBe("");
    expect(defaultPlanPrefix(true, 120)).toBe("");
  });

  it("keeps IPv4 at block prefix + 8, capped at /32", () => {
    expect(defaultPlanPrefix(false, 22)).toBe("30");
    expect(defaultPlanPrefix(false, 28)).toBe("32");
  });

  it("says first-fit, which is what the planner does", () => {
    prefixField("10.201.8.0/22");
    expect(screen.getByText(/first-fit/)).toBeTruthy();
    expect(screen.queryByText(/best-fit/)).toBeNull();
  });
});
