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
import { AxiosError, type InternalAxiosRequestConfig } from "axios";

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

const renderGroup = (g: DHCPServerGroup) => {
  stored = g;
  render(
    <QueryClientProvider client={new QueryClient()}>
      <CreateServerGroupModal group={g} onClose={() => {}} />
    </QueryClientProvider>,
  );
};

describe("hidden HA timers (standalone) (#3371)", () => {
  it("a stored Max Unacked Clients of 0 is not rewritten to 5 by an unrelated save", async () => {
    updateGroup.mockResolvedValue({});
    renderGroup({
      ...group,
      mode: "standalone",
      max_unacked_clients: 0,
    } as unknown as DHCPServerGroup);
    const name = (await screen.findByText("Name", { selector: "label" }))
      .nextElementSibling as HTMLInputElement;
    fireEvent.change(name, { target: { value: "renamed" } });
    fireEvent.submit(name.form!);
    await vi.waitFor(() => expect(updateGroup).toHaveBeenCalled());
    expect(updateGroup.mock.calls[0][1]).toEqual({ name: "renamed" });
  });
});

describe("save errors (#3371)", () => {
  const cfg = { headers: {} } as InternalAxiosRequestConfig;
  const submitWith = async (err: unknown) => {
    updateGroup.mockRejectedValue(err);
    renderGroup(group);
    const name = (await screen.findByText("Name", { selector: "label" }))
      .nextElementSibling as HTMLInputElement;
    fireEvent.change(name, { target: { value: "renamed" } });
    fireEvent.submit(name.form!);
  };

  it("a network failure reads as the dialog's own message, not axios's", async () => {
    await submitWith(
      new AxiosError("Network Error", "ERR_NETWORK", cfg, {}, undefined),
    );
    await screen.findByText("Failed to save group");
    expect(screen.queryByText("Network Error")).toBeNull();
  });

  it("a server detail is still shown", async () => {
    await submitWith(
      new AxiosError(
        "Request failed",
        "ERR_BAD_REQUEST",
        cfg,
        {},
        {
          status: 409,
          statusText: "Conflict",
          headers: {},
          config: cfg,
          data: { detail: "A group named renamed already exists" },
        },
      ),
    );
    await screen.findByText("A group named renamed already exists");
  });
});
