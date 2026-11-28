/**
 * @vitest-environment jsdom
 *
 * The drilldown's Delete opens the revoke dialog, so it follows the same
 * rule and reason as the table's Revoke (#4613): the server refuses the
 * only control-plane node with 409.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { ApplianceDrilldownModal } from "./FleetTab";
import type { ApplianceRow } from "@/lib/api";

afterEach(cleanup);

function setup(variant: string) {
  const onDelete = vi.fn();
  const noop = () => {};
  const row = {
    id: "a1",
    hostname: "seed",
    state: "approved",
    capabilities: {},
    appliance_variant: variant,
  } as unknown as ApplianceRow;
  render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>
        <ApplianceDrilldownModal
          row={row}
          onClose={noop}
          onApprove={noop}
          approving={false}
          onReject={noop}
          onRekey={noop}
          onDelete={onDelete}
          onRowUpdated={noop}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return onDelete;
}

describe("drilldown Delete on a control-plane row (#4613)", () => {
  it("is disabled with the table's reason and opens nothing", () => {
    const onDelete = setup("control-plane");
    const btn = screen.getByRole("button", { name: /delete/i });
    expect((btn as HTMLButtonElement).disabled).toBe(true);
    expect(btn.getAttribute("title")).toBe(
      "Demote this node from the control-plane cluster first (Manage control plane cluster…) before revoking.",
    );
    fireEvent.click(btn);
    expect(onDelete).not.toHaveBeenCalled();
  });

  it("stays enabled on a service-agent row", () => {
    const onDelete = setup("appliance");
    const btn = screen.getByRole("button", { name: /delete/i });
    expect((btn as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(btn);
    expect(onDelete).toHaveBeenCalledTimes(1);
  });
});
