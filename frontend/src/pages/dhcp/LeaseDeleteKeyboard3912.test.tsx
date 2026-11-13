/**
 * @vitest-environment jsdom
 *
 * #3912: Delete lease opened only from a lease row's right-click menu, which a
 * keyboard user cannot open. A superadmin's row carries a Delete button.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

let superadmin = true;
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    ipamApi: { ...actual.ipamApi, listSubnets: () => Promise.resolve([]) },
    dhcpApi: {
      ...actual.dhcpApi,
      getLeases: () =>
        Promise.resolve({
          items: [
            {
              id: "l1",
              ip_address: "10.0.0.9",
              mac_address: "02:00:00:00:00:09",
              duid: null,
              iaid: null,
              hostname: "h9",
              state: "active",
              expires_at: null,
              last_seen_at: null,
            },
          ],
          total: 1,
          page: 1,
          page_size: 100,
        }),
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
      can: () => true,
      isSuperadmin: superadmin,
    }),
  };
});

const { LeasesTab } = await import("./DHCPPage");
afterEach(cleanup);

function mount() {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <LeasesTab server={{ id: "s1" } as never} />
    </QueryClientProvider>,
  );
}

describe("DHCP lease row keyboard path (#3912)", () => {
  it("a superadmin tabs to Delete lease and opens the confirm with Enter", async () => {
    superadmin = true;
    const user = userEvent.setup();
    mount();
    const del = await screen.findByRole("button", {
      name: "Delete lease 10.0.0.9",
    });
    del.focus();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("dialog", { name: "Delete Lease" })).toBeTruthy();
    await user.keyboard("{Escape}");
    expect(document.activeElement).toBe(del);
  });

  it("offers no Delete button to a non-superadmin", async () => {
    superadmin = false;
    mount();
    await screen.findByText("10.0.0.9");
    expect(screen.queryByRole("button", { name: /Delete lease/ })).toBeNull();
  });
});
