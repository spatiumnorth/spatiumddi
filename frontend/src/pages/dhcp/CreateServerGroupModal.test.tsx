/**
 * @vitest-environment jsdom
 *
 * #2480 — Max Unacked Clients of 0 is a value the field offers (min 0) and
 * must be sent as 0, by New and by an untouched Edit.
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
import type { DHCPServerGroup } from "@/lib/api";

const createGroup = vi.fn();
const updateGroup = vi.fn();
vi.mock("@/lib/api", () => ({
  dhcpApi: {
    createGroup: (...a: unknown[]) => createGroup(...a),
    updateGroup: (...a: unknown[]) => updateGroup(...a),
  },
}));

const { CreateServerGroupModal } = await import("./CreateServerGroupModal");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function ui(group?: DHCPServerGroup) {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <CreateServerGroupModal group={group} onClose={() => {}} />
    </QueryClientProvider>,
  );
}
const unacked = () =>
  screen.getByText("Max Unacked Clients", { selector: "label" })
    .nextElementSibling as HTMLInputElement;

describe("Max Unacked Clients 0 (#2480)", () => {
  it("New sends the 0 it shows", async () => {
    createGroup.mockResolvedValue({ id: "g" });
    ui();
    fireEvent.change(screen.getAllByRole("combobox")[0], {
      target: { value: "hot-standby" },
    });
    fireEvent.change(unacked(), { target: { value: "0" } });
    expect(unacked().value).toBe("0");
    fireEvent.submit(unacked().form!);
    await waitFor(() => expect(createGroup).toHaveBeenCalled());
    expect(createGroup.mock.calls[0][0].max_unacked_clients).toBe(0);
  });

  it("an untouched Edit of a group stored with 0 keeps 0", async () => {
    updateGroup.mockResolvedValue({ id: "g" });
    ui({
      id: "g",
      name: "ha",
      description: "",
      mode: "hot-standby",
      max_unacked_clients: 0,
    } as unknown as DHCPServerGroup);
    expect(unacked().value).toBe("0");
    fireEvent.submit(unacked().form!);
    await waitFor(() => expect(updateGroup).toHaveBeenCalled());
    expect(updateGroup.mock.calls[0][1].max_unacked_clients).toBe(0);
  });
});
