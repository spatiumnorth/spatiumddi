/**
 * @vitest-environment jsdom
 *
 * #3487: Edit Static Assignment opened only from a row's right-click menu, so
 * a keyboard user could not reach it. The row carries Edit / Delete buttons.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

let allowed = true;
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
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
            id: "st1",
            scope_id: "sc1",
            mac_address: "02:00:00:00:00:01",
            ip_address: "10.0.0.5",
            hostname: "h1",
            description: "",
            client_id: null,
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
  return { ...actual, usePermissions: () => ({ can: () => allowed }) };
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

describe("static assignment row actions (#3487)", () => {
  it("opens Edit Static Assignment with the keyboard alone", async () => {
    allowed = true;
    const user = userEvent.setup();
    mount();
    await screen.findByText("10.0.0.5");
    const edit = screen.getByRole("button", {
      name: "Edit static assignment 10.0.0.5",
    });
    for (let i = 0; i < 30 && document.activeElement !== edit; i++) {
      await user.tab();
    }
    expect(document.activeElement).toBe(edit);
    await user.keyboard("{Enter}");
    expect(await screen.findByText("Edit Static Assignment")).toBeTruthy();
  });

  it("is disabled with the reason when the role cannot write", async () => {
    allowed = false;
    mount();
    await screen.findByText("10.0.0.5");
    const edit = screen.getByRole("button", {
      name: "Edit static assignment 10.0.0.5",
    }) as HTMLButtonElement;
    expect(edit.disabled).toBe(true);
    expect(edit.title).toBe(
      "Requires write permission on DHCP static assignments",
    );
  });
});
