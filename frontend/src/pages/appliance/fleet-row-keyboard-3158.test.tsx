/**
 * @vitest-environment jsdom
 *
 * The Fleet row's detail dialog opens from the keyboard too (#3158): the
 * row's click opened it, and nothing a keyboard reaches did.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { ApplianceTableRow } from "./FleetTab";
import type { ApplianceRow } from "@/lib/api";

afterEach(cleanup);

const row = {
  id: "a1",
  hostname: "ddipg-seed",
  state: "approved",
  capabilities: {},
  appliance_variant: "control-plane",
} as unknown as ApplianceRow;

function setup() {
  const onOpen = vi.fn();
  const noop = () => {};
  const qc = new QueryClient();
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <table>
          <tbody>
            <ApplianceTableRow
              row={row}
              onOpen={onOpen}
              onApprove={noop}
              onReject={noop}
              onRekey={noop}
              onDelete={noop}
              onReauthorize={noop}
              onPermanentDelete={noop}
            />
          </tbody>
        </table>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return onOpen;
}

describe("Fleet row keyboard path (#3158)", () => {
  it("still opens on a click of the row", () => {
    const onOpen = setup();
    fireEvent.click(screen.getByText("control-plane").closest("tr")!);
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it("has a named button that opens the detail on Enter and Space", async () => {
    const onOpen = setup();
    const btn = screen.getByRole("button", { name: "ddipg-seed" });
    expect(btn.getAttribute("title")).toBe("View details");
    const user = userEvent.setup();
    await user.tab();
    // Reached by Tab before any action in the row.
    expect(document.activeElement).toBe(btn);
    await user.keyboard("{Enter}");
    expect(onOpen).toHaveBeenCalledTimes(1);
    await user.keyboard(" ");
    expect(onOpen).toHaveBeenCalledTimes(2);
  });

  it("does not open twice for one click on the button", () => {
    const onOpen = setup();
    fireEvent.click(screen.getByRole("button", { name: "ddipg-seed" }));
    expect(onOpen).toHaveBeenCalledTimes(1);
  });
});
