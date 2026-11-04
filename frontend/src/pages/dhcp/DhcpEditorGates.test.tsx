/**
 * @vitest-environment jsdom
 *
 * The DHCP data tabs offer a write to exactly the callers the server lets
 * make it (#1861).
 *
 * MAC blocks and PXE profiles took a superadmin until #1861; they now check
 * the route's own resource permission (``dhcp_mac_block``, and
 * ``dhcp_scope`` for PXE profiles), with ``delete`` for a delete. So the
 * built-in DHCP Editor gets every control, a Viewer gets none of them, and a
 * role granted write without delete gets the writes only. These run the real
 * `usePermissions` hook against the permission set
 * `GET /auth/me/permissions` returns.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { MyPermissions } from "@/lib/api";

const myPermissions = vi.fn<() => Promise<MyPermissions>>();

vi.mock("@/lib/api", () => ({
  authApi: { myPermissions: () => myPermissions() },
  DHCP_PXE_ARCH_LABELS: {},
  dhcpApi: {
    listMacBlocks: () =>
      Promise.resolve([
        {
          id: "blk-1",
          group_id: "grp-1",
          mac_address: "aa:bb:cc:dd:ee:ff",
          reason: "rogue",
          description: "",
          enabled: true,
          expires_at: null,
          created_at: "2026-10-01T00:00:00.000Z",
          modified_at: "2026-10-01T00:00:00.000Z",
          created_by_user_id: null,
          updated_by_user_id: null,
          last_match_at: null,
          match_count: 0,
          vendor: null,
          ipam_matches: [],
        },
      ]),
    listPxeProfiles: () =>
      Promise.resolve([
        {
          id: "pxe-1",
          group_id: "grp-1",
          name: "lab",
          description: "",
          next_server: "10.0.0.5",
          enabled: true,
          matches: [],
        },
      ]),
  },
}));

const { MacBlocksTab } = await import("./MacBlocksTab");
const { PXEProfilesPage } = await import("./PXEProfilesPage");

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

const DHCP_EDITOR = grants(
  ["admin", "dhcp_server"],
  ["admin", "dhcp_scope"],
  ["admin", "dhcp_pool"],
  ["admin", "dhcp_static"],
  ["admin", "dhcp_client_class"],
  ["admin", "dhcp_option_template"],
  ["admin", "dhcp_mac_block"],
);
const VIEWER = grants(["read", "*"]);

function wrap(ui: React.ReactNode, perms: MyPermissions) {
  myPermissions.mockResolvedValue(perms);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/dhcp/groups/grp-1/pxe"]}>
        <Routes>
          <Route path="/dhcp/groups/:groupId/pxe" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** A refused icon-only button is named by its action (aria-label, #3395) and
 *  carries the refusal reason as its tooltip: find it by either. */
function gated(name: string | RegExp): HTMLElement {
  const byRole = screen.queryAllByRole("button", { name });
  if (byRole.length === 1) return byRole[0];
  // Only the icon buttons carry an aria-label; a text button's title is
  // the same reason and must not make the lookup ambiguous.
  const byTitle = screen
    .queryAllByTitle(name)
    .filter((el) => el.hasAttribute("aria-label"));
  if (byTitle.length !== 1) return screen.getByTitle(name);
  return byTitle[0];
}

function button(name: string | RegExp): HTMLButtonElement {
  return gated(name) as HTMLButtonElement;
}

afterEach(() => {
  cleanup();
  myPermissions.mockReset();
});

describe("MAC blocks tab (#1861)", () => {
  it("offers the built-in DHCP Editor every write", async () => {
    wrap(<MacBlocksTab groupId="grp-1" />, DHCP_EDITOR);
    await screen.findByText("aa:bb:cc:dd:ee:ff");
    await waitFor(() => expect(button(/Block MAC/).disabled).toBe(false));
    expect(button("Edit").disabled).toBe(false);
    expect(button("Delete").disabled).toBe(false);
  });

  it("offers a Viewer none of them, and says why", async () => {
    wrap(<MacBlocksTab groupId="grp-1" />, VIEWER);
    await screen.findByText("aa:bb:cc:dd:ee:ff");
    await waitFor(() => expect(button(/Block MAC/).disabled).toBe(true));
    expect(button(/Block MAC/).title).toBe(
      "Requires write permission on DHCP MAC blocks",
    );
    expect(
      button("Requires write permission on DHCP MAC blocks").disabled,
    ).toBe(true);
    expect(
      button("Requires delete permission on DHCP MAC blocks").disabled,
    ).toBe(true);
  });

  it("offers a role with write but not delete the writes only", async () => {
    wrap(
      <MacBlocksTab groupId="grp-1" />,
      grants(["read", "*"], ["write", "dhcp_mac_block"]),
    );
    await screen.findByText("aa:bb:cc:dd:ee:ff");
    await waitFor(() => expect(button(/Block MAC/).disabled).toBe(false));
    expect(button("Edit").disabled).toBe(false);
    expect(
      button("Requires delete permission on DHCP MAC blocks").disabled,
    ).toBe(true);
  });
});

describe("PXE profiles page (#1861)", () => {
  it("offers the built-in DHCP Editor every write", async () => {
    wrap(<PXEProfilesPage />, DHCP_EDITOR);
    await screen.findByText("lab");
    await waitFor(() => expect(button(/New profile/).disabled).toBe(false));
    expect(button("Edit").disabled).toBe(false);
    expect(button("Delete").disabled).toBe(false);
  });

  it("offers a Viewer none of them", async () => {
    wrap(<PXEProfilesPage />, VIEWER);
    await screen.findByText("lab");
    await waitFor(() => expect(button(/New profile/).disabled).toBe(true));
    expect(button(/New profile/).title).toBe(
      "Requires write permission on DHCP scopes",
    );
    expect(button("Requires write permission on DHCP scopes").disabled).toBe(
      true,
    );
    expect(button("Requires delete permission on DHCP scopes").disabled).toBe(
      true,
    );
  });
});
