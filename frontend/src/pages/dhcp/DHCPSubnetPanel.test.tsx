/**
 * @vitest-environment jsdom
 *
 * The IPAM subnet's DHCP tab offers only the writes the caller's grants
 * pass (#1155).
 *
 * The server refuses a scope or pool write without `write` (or `delete`) on
 * `dhcp_scope` / `dhcp_pool`, and audits the denial; the console used to
 * offer every control anyway, so a read-only operator filled in a form and
 * met "Permission denied" at submit. These run the real `usePermissions`
 * hook against the permission set `GET /auth/me/permissions` returns.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { MyPermissions } from "@/lib/api";

const myPermissions = vi.fn<() => Promise<MyPermissions>>();

vi.mock("@/lib/api", () => ({
  authApi: { myPermissions: () => myPermissions() },
  dhcpApi: {
    listScopesBySubnet: () =>
      Promise.resolve([
        {
          id: "scope-1",
          name: "staff",
          subnet_id: "sub-1",
          lease_time: 86400,
          enabled: true,
          ddns_enabled: false,
        },
      ]),
    listPools: () =>
      Promise.resolve([
        {
          id: "pool-1",
          name: "default",
          start_ip: "10.78.21.10",
          end_ip: "10.78.21.254",
          pool_type: "dynamic",
        },
      ]),
  },
}));
vi.mock("./WindowsFailoverPanel", () => ({ ScopeServingStrip: () => null }));
vi.mock("./CreateScopeModal", () => ({ CreateScopeModal: () => null }));
vi.mock("./CreatePoolModal", () => ({ CreatePoolModal: () => null }));

const { DHCPSubnetPanel } = await import("./DHCPSubnetPanel");

function grants(...g: [string, string][]): MyPermissions {
  return {
    is_superadmin: false,
    grants: g.map(([action, resource_type]) => ({
      action,
      resource_type,
      resource_id: null,
    })),
  } as MyPermissions;
}

async function openPanel(perms: MyPermissions) {
  myPermissions.mockResolvedValue(perms);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <DHCPSubnetPanel subnetId="sub-1" />
    </QueryClientProvider>,
  );
  // The pool row is the last thing to render; by then the permission set
  // has been asked for too.
  await screen.findByText("10.78.21.10");
  await waitFor(() => expect(myPermissions).toHaveBeenCalled());
  // Let the answer land: while it is loading every gate is closed
  // (usePermissions fails closed), which would pass the Viewer case for
  // the wrong reason.
  await act(async () => {});
}

function button(name: string | RegExp): HTMLButtonElement {
  return screen.getByRole("button", { name }) as HTMLButtonElement;
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("DHCPSubnetPanel write controls (#1155)", () => {
  it("offers a Viewer none of them, and says why", async () => {
    // The built-in Viewer role: read on everything.
    await openPanel(grants(["read", "*"]));
    await waitFor(() => expect(button(/Create Scope/).disabled).toBe(true));
    expect(button(/Create Scope/).title).toBe(
      "Requires write permission on DHCP scopes",
    );
    expect(button(/Add Pool/).disabled).toBe(true);
    // The icon buttons are named by their tooltip, which is the reason
    // while it is denied: edit + delete scope, edit + delete pool.
    const denied = screen.getAllByRole("button", {
      name: /^Requires (write|delete) permission on DHCP (scopes|pools)$/,
    }) as HTMLButtonElement[];
    expect(denied).toHaveLength(4);
    expect(denied.every((b) => b.disabled)).toBe(true);
    const toggle = screen.getByRole("checkbox", { name: /Enabled/ });
    expect((toggle as HTMLInputElement).disabled).toBe(true);
  });

  it("offers an operator who may write but not delete exactly the writes", async () => {
    await openPanel(
      grants(["read", "*"], ["write", "dhcp_scope"], ["write", "dhcp_pool"]),
    );
    await waitFor(() => expect(button(/Create Scope/).disabled).toBe(false));
    expect(button(/Add Pool/).disabled).toBe(false);
    expect(button("Edit scope").disabled).toBe(false);
    expect(button("Edit pool").disabled).toBe(false);
    expect(button("Requires delete permission on DHCP scopes").disabled).toBe(
      true,
    );
    expect(button("Requires delete permission on DHCP pools").disabled).toBe(
      true,
    );
  });

  it("offers a superadmin everything", async () => {
    await openPanel({ is_superadmin: true, grants: [] } as MyPermissions);
    await waitFor(() => expect(button(/Create Scope/).disabled).toBe(false));
    for (const name of [
      /Add Pool/,
      "Edit scope",
      "Delete scope",
      "Edit pool",
      "Delete pool",
    ]) {
      expect(button(name).disabled).toBe(false);
    }
  });
});
