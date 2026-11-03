/**
 * @vitest-environment jsdom
 *
 * #3371 — a blank HA timer in Edit Server Group was saved as its default
 * (10000 / 60000 / 10000), a number the field never showed. The dialog
 * refuses it with a reason and sends nothing.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { DHCPServerGroup } from "@/lib/api";

const updateGroup = vi.fn();
let stored: unknown;
vi.mock("@/lib/api", () => ({
  dhcpApi: {
    createGroup: vi.fn(),
    updateGroup: (...a: unknown[]) => updateGroup(...a),
    getGroup: () => Promise.resolve(stored),
  },
}));

const { CreateServerGroupModal } = await import("./CreateServerGroupModal");
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const group = {
  id: "g",
  name: "ha",
  description: "",
  mode: "hot-standby",
  heartbeat_delay_ms: 5000,
  max_response_delay_ms: 30000,
  max_ack_delay_ms: 2000,
  max_unacked_clients: 3,
} as unknown as DHCPServerGroup;

const field = (label: string) =>
  screen.getByText(label, { selector: "label" })
    .nextElementSibling as HTMLInputElement;

describe.each([
  ["Heartbeat Delay (ms)", "5000"],
  ["Max Response Delay (ms)", "30000"],
  ["Max Ack Delay (ms)", "2000"],
  ["Max Unacked Clients", "3"],
])("a cleared %s (#3371)", (label, storedVal) => {
  it("is refused with a reason and nothing is sent", async () => {
    stored = group;
    render(
      <QueryClientProvider client={new QueryClient()}>
        <CreateServerGroupModal group={group} onClose={() => {}} />
      </QueryClientProvider>,
    );
    stored = group;
    expect(await screen.findByText(label, { selector: "label" })).toBeTruthy();
    expect(field(label).value).toBe(storedVal);
    fireEvent.change(field(label), { target: { value: "" } });
    fireEvent.submit(field(label).form!);
    await screen.findByText(
      new RegExp(`${label.replace(/ \(ms\)/, "")} must be`),
    );
    expect(updateGroup).not.toHaveBeenCalled();
  });
});
