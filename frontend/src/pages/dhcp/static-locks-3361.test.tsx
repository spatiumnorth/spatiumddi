/**
 * @vitest-environment jsdom
 *
 * #3361: a locked DHCP reservation shows its padlock, its Delete is disabled
 * with the reason in the title, Edit says what is frozen, a holder of the
 * `lock` grant gets Lock / Unlock, and the "Locked" filter narrows the list.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

let granted = new Set<string>();
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const base = {
    scope_id: "sc1",
    description: "",
    client_id: null,
    hostname: "h",
  };
  return {
    ...actual,
    dhcpApi: {
      ...actual.dhcpApi,
      listScopesByGroup: () =>
        Promise.resolve([
          { id: "sc1", name: "lan", subnet_id: "sn1", address_family: "ipv4" },
        ]),
      listStatics: () =>
        Promise.resolve([
          {
            ...base,
            id: "st1",
            mac_address: "02:00:00:00:00:01",
            ip_address: "10.0.0.5",
            lock_level: "edit",
            locked_by: "alice",
            lock_reason: "PCI freeze",
          },
          {
            ...base,
            id: "st2",
            mac_address: "02:00:00:00:00:02",
            ip_address: "10.0.0.6",
            lock_level: null,
          },
        ]),
      listPools: () => Promise.resolve([]),
    },
  };
});
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: (action: string, resource: string) =>
        granted.has(`${action}:${resource}`),
    }),
  };
});

const { ServerPoolsOrStaticsTab } = await import("./DHCPPage");
afterEach(cleanup);

function mount() {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ServerPoolsOrStaticsTab groupId="g1" kind="statics" />
    </QueryClientProvider>,
  );
}

describe("locked static reservations (#3361)", () => {
  it("disables Delete with the reason, hints Edit, and badges the row", async () => {
    granted = new Set(["write:dhcp_static", "delete:dhcp_static"]);
    mount();
    await screen.findByText("10.0.0.5");
    const del = screen.getByRole("button", {
      name: "Delete static assignment 10.0.0.5",
    }) as HTMLButtonElement;
    expect(del.disabled).toBe(true);
    expect(del.title).toContain("PCI freeze");
    expect(del.title).toContain("alice");
    const edit = screen.getByRole("button", {
      name: "Edit static assignment 10.0.0.5",
    }) as HTMLButtonElement;
    expect(edit.disabled).toBe(false);
    expect(edit.title).toContain("description");
    expect(screen.getAllByTestId("lock-badge")).toHaveLength(1);
    // The unlocked row is untouched.
    const other = screen.getByRole("button", {
      name: "Delete static assignment 10.0.0.6",
    }) as HTMLButtonElement;
    expect(other.disabled).toBe(false);
  });

  it("offers Lock / Unlock only behind the lock grant", async () => {
    granted = new Set(["write:dhcp_static", "delete:dhcp_static"]);
    mount();
    await screen.findByText("10.0.0.5");
    expect(screen.queryByLabelText(/^Unlock static assignment/)).toBeNull();
    cleanup();
    granted = new Set(["lock:dhcp_static"]);
    mount();
    await screen.findByText("10.0.0.5");
    expect(
      screen.getByLabelText("Unlock static assignment 10.0.0.5"),
    ).toBeTruthy();
    expect(
      screen.getByLabelText("Lock static assignment 10.0.0.6"),
    ).toBeTruthy();
  });

  it("the Locked filter narrows the list to locked rows, or to unlocked", async () => {
    granted = new Set();
    mount();
    await screen.findByText("10.0.0.5");
    const select = screen.getByLabelText("Filter by lock");
    fireEvent.change(select, { target: { value: "locked" } });
    expect(screen.queryByText("10.0.0.6")).toBeNull();
    expect(screen.getByText("10.0.0.5")).toBeTruthy();
    fireEvent.change(select, { target: { value: "unlocked" } });
    expect(screen.queryByText("10.0.0.5")).toBeNull();
    expect(screen.getByText("10.0.0.6")).toBeTruthy();
    fireEvent.change(select, { target: { value: "all" } });
    expect(screen.getByText("10.0.0.5")).toBeTruthy();
    expect(screen.getByText("10.0.0.6")).toBeTruthy();
  });
});
