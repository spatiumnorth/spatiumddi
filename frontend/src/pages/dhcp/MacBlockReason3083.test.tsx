/**
 * @vitest-environment jsdom
 *
 * #3083 — a MAC block made from New Devices carries the operator's free text
 * as its reason. Edit MAC Block showed "Rogue device" for it and an untouched
 * Save overwrote it. The dialog now shows and keeps the stored reason.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const updateMacBlock = vi.fn(() => Promise.resolve({}));
const block = {
  id: "b1",
  group_id: "g1",
  mac_address: "02:98:14:00:00:99",
  reason: "xp found on desk",
  description: "",
  enabled: true,
  expires_at: null,
  created_at: "2026-10-29T00:00:00Z",
  modified_at: "2026-10-29T00:00:00Z",
  created_by_user_id: null,
  updated_by_user_id: null,
  last_match_at: null,
  match_count: 0,
  vendor: null,
  ipam_matches: [],
};
vi.mock("@/lib/api", () => ({
  dhcpApi: {
    listMacBlocks: () => Promise.resolve([block]),
    updateMacBlock: (...a: unknown[]) => (updateMacBlock as any)(...a),
  },
}));
vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ can: () => true }),
  permissionGate: () => true,
  useCan: () => true,
}));

const mod = await import("./MacBlocksTab");
afterEach(() => {
  cleanup();
  updateMacBlock.mockClear();
});

describe("Edit MAC Block reason (#3083)", () => {
  it("shows the stored free-text reason and an untouched Save keeps it", async () => {
    const Tab = (mod as any).MacBlocksTab ?? (mod as any).default;
    render(
      <QueryClientProvider client={new QueryClient()}>
        <Tab groupId="g1" />
      </QueryClientProvider>,
    );
    // The list's pill prints the text rather than nothing.
    await waitFor(() =>
      expect(screen.getAllByText("xp found on desk").length).toBeGreaterThan(0),
    );
    fireEvent.click(screen.getByTitle("Edit"));
    const select = (await screen.findByText("Reason", { selector: "label" }))
      .nextElementSibling as HTMLSelectElement;
    expect(select.value).toBe("xp found on desk");
    fireEvent.submit(select.closest("form")!);
    await waitFor(() => expect(updateMacBlock).toHaveBeenCalled());
    expect((updateMacBlock.mock.calls[0] as unknown[])[2]).toMatchObject({
      reason: "xp found on desk",
    });
  });
});
