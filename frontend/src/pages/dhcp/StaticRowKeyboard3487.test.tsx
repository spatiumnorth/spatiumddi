/**
 * @vitest-environment jsdom
 *
 * #3487: Edit Static Assignment opened only from a row's right-click menu, so
 * a keyboard user could not reach it. The row carries Edit / Delete buttons.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// Which (action, resource) pairs the role holds; every test sets it.
let granted = new Set<string>();
const deleteStatic = vi.fn();
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
          {
            id: "st2",
            scope_id: "sc1",
            mac_address: "02:00:00:00:00:02",
            ip_address: "10.0.0.6",
            hostname: "h2",
            description: "",
            client_id: null,
          },
        ]),
      listPools: () => Promise.resolve([]),
      deleteStatic: (...args: unknown[]) => deleteStatic(...args),
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
afterEach(() => {
  cleanup();
  deleteStatic.mockReset();
});

const ALL = ["write:dhcp_static", "delete:dhcp_static"];

function mount() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { mutations: { retry: false } } })
      }
    >
      <ServerPoolsOrStaticsTab groupId="g1" kind="statics" />
    </QueryClientProvider>,
  );
}

async function tabTo(user: ReturnType<typeof userEvent.setup>, el: Element) {
  for (let i = 0; i < 40 && document.activeElement !== el; i++) {
    await user.tab();
  }
  expect(document.activeElement).toBe(el);
}

describe("static assignment row actions (#3487)", () => {
  it("opens Edit Static Assignment with the keyboard alone", async () => {
    granted = new Set(ALL);
    const user = userEvent.setup();
    mount();
    await screen.findByText("10.0.0.5");
    const edit = screen.getByRole("button", {
      name: "Edit static assignment 10.0.0.5",
    });
    await tabTo(user, edit);
    await user.keyboard("{Enter}");
    expect(await screen.findByText("Edit Static Assignment")).toBeTruthy();
    // Closing it puts the keyboard user back on the row's button.
    await user.keyboard("{Escape}");
    await waitFor(() =>
      expect(screen.queryByText("Edit Static Assignment")).toBeNull(),
    );
    expect(document.activeElement).toBe(edit);
  });

  it("opens the Delete confirm with the keyboard alone", async () => {
    granted = new Set(ALL);
    const user = userEvent.setup();
    mount();
    await screen.findByText("10.0.0.5");
    const del = screen.getByRole("button", {
      name: "Delete static assignment 10.0.0.5",
    });
    await tabTo(user, del);
    await user.keyboard("{Enter}");
    expect(await screen.findByText("Delete Static Assignment")).toBeTruthy();
    expect(
      screen.getByText("Delete reservation 10.0.0.5 (02:00:00:00:00:01)?"),
    ).toBeTruthy();
  });

  it("shows the server's refusal, and not on the next row's confirm", async () => {
    granted = new Set(ALL);
    deleteStatic.mockRejectedValue({
      response: {
        status: 403,
        data: { detail: "Permission denied: need 'delete' on 'dhcp_static'" },
      },
    });
    const user = userEvent.setup();
    mount();
    await screen.findByText("10.0.0.5");
    await user.click(
      screen.getByRole("button", { name: "Delete static assignment 10.0.0.5" }),
    );
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: /^Delete$/ }));
    expect((await screen.findByRole("alert")).textContent).toBe(
      "Permission denied: need 'delete' on 'dhcp_static'",
    );
    await user.keyboard("{Escape}");
    await waitFor(() =>
      expect(screen.queryByText("Delete Static Assignment")).toBeNull(),
    );
    await user.click(
      screen.getByRole("button", { name: "Delete static assignment 10.0.0.6" }),
    );
    await screen.findByText("Delete reservation 10.0.0.6 (02:00:00:00:00:02)?");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("Edit is disabled with the reason when the role cannot write", async () => {
    granted = new Set(["delete:dhcp_static"]);
    mount();
    await screen.findByText("10.0.0.5");
    const edit = screen.getByRole("button", {
      name: "Edit static assignment 10.0.0.5",
    }) as HTMLButtonElement;
    expect(edit.disabled).toBe(true);
    expect(edit.title).toBe(
      "Requires write permission on DHCP static assignments",
    );
    const del = screen.getByRole("button", {
      name: "Delete static assignment 10.0.0.5",
    }) as HTMLButtonElement;
    expect(del.disabled).toBe(false);
  });

  it("Delete is disabled with the reason when the role cannot delete", async () => {
    granted = new Set(["write:dhcp_static"]);
    mount();
    await screen.findByText("10.0.0.5");
    const del = screen.getByRole("button", {
      name: "Delete static assignment 10.0.0.5",
    }) as HTMLButtonElement;
    expect(del.disabled).toBe(true);
    expect(del.title).toBe(
      "Requires delete permission on DHCP static assignments",
    );
    const edit = screen.getByRole("button", {
      name: "Edit static assignment 10.0.0.5",
    }) as HTMLButtonElement;
    expect(edit.disabled).toBe(false);
  });
});
