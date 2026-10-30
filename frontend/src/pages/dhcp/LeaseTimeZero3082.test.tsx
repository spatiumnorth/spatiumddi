/**
 * @vitest-environment jsdom
 *
 * #3082 — a Lease Time typed as 0 was saved as 86400 through `|| 86400`.
 * The API refuses 0, so the dialog must refuse it with a reason and send
 * nothing, never swap in a lease the field does not show.
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
import type { DHCPScope } from "@/lib/api";

const updateScope = vi.fn(() => Promise.resolve({}));
// The row the dialog's fresh read (#3077) answers with.
let freshScope: unknown;
vi.mock("@/lib/api", async (importOriginal) => ({
  // Real helpers (formatApiError, …); only the API clients are stubbed.
  ...(await importOriginal<typeof import("@/lib/api")>()),
  dhcpApi: {
    listGroups: () =>
      Promise.resolve([{ id: "g-a", name: "group-a", mode: "standalone" }]),
    listOptionCodes: () => Promise.resolve([]),
    listOptionTemplates: () => Promise.resolve([]),
    listPxeProfiles: () => Promise.resolve([]),
    // #3077 reads the scope fresh on open, and renders nothing until it has.
    getScope: () => Promise.resolve(freshScope),
    updateScope: (...a: unknown[]) => (updateScope as any)(...a),
  },
  ipamApi: {
    getSubnet: () =>
      Promise.resolve({ id: "sub-a", network: "10.0.0.0/24", gateway: null }),
    listSubnets: () => Promise.resolve([]),
    getEffectiveSubnetDhcp: () => Promise.resolve({}),
  },
  settingsApi: { get: () => Promise.resolve({}) },
}));
vi.mock("./windowsFailover", () => ({
  GROUP_FAILOVER_QUERY_KEY: "dhcp-group-failover",
  useGroupFailover: () => ({ data: undefined }),
}));

const { CreateScopeModal } = await import("./CreateScopeModal");
afterEach(() => {
  cleanup();
  updateScope.mockClear();
});

async function open() {
  const scope = {
    id: "s1",
    subnet_id: "sub-a",
    group_id: "g-a",
    name: "x",
    lease_time: 3600,
    options: [],
  } as unknown as DHCPScope;
  freshScope = scope;
  render(
    <QueryClientProvider client={new QueryClient()}>
      <CreateScopeModal scope={scope} onClose={() => {}} />
    </QueryClientProvider>,
  );
  return (await screen.findByText("Lease Time (sec)", { selector: "label" }))
    .nextElementSibling as HTMLInputElement;
}

describe("Edit DHCP Scope lease time (#3082)", () => {
  it("refuses a lease time of 0 and sends nothing", async () => {
    const box = await open();
    expect(box.value).toBe("3600");
    fireEvent.change(box, { target: { value: "0" } });
    fireEvent.submit(box.closest("form")!);
    await waitFor(() =>
      expect(screen.getByText(/Lease time must be/i)).toBeTruthy(),
    );
    expect(updateScope).not.toHaveBeenCalled();
  });

  it("refuses a cleared lease time too", async () => {
    const box = await open();
    fireEvent.change(box, { target: { value: "" } });
    fireEvent.submit(box.closest("form")!);
    await waitFor(() =>
      expect(screen.getByText(/Lease time must be/i)).toBeTruthy(),
    );
    expect(updateScope).not.toHaveBeenCalled();
  });

  it("sends the lease time the field shows", async () => {
    const box = await open();
    fireEvent.change(box, { target: { value: "7200" } });
    fireEvent.submit(box.closest("form")!);
    await waitFor(() => expect(updateScope).toHaveBeenCalled());
    expect((updateScope.mock.calls[0] as unknown[])[1]).toMatchObject({
      lease_time: 7200,
    });
  });

  it("shows the generic message, not a raw JS error, for an unexpected failure", async () => {
    updateScope.mockImplementationOnce(() =>
      Promise.reject(
        new TypeError("Cannot read properties of undefined (reading 'x')"),
      ),
    );
    const box = await open();
    // A change, so the save is sent: an unchanged Save sends nothing (#3091).
    fireEvent.change(box, { target: { value: "7200" } });
    fireEvent.submit(box.closest("form")!);
    await waitFor(() =>
      expect(screen.getByText("Failed to save scope")).toBeTruthy(),
    );
    expect(screen.queryByText(/Cannot read properties/)).toBeNull();
  });
});
