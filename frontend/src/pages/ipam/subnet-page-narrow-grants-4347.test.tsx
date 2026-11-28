/**
 * @vitest-environment jsdom
 *
 * The subnet page as a user with narrow grants sees it (#4347, #4348, #4349):
 * a refused scope list or effective DDNS read is not drawn as data, and an
 * alias delete the server refuses is not offered.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}
const refused = () =>
  Promise.reject(
    Object.assign(new Error("forbidden"), {
      isAxiosError: true,
      response: { status: 403, data: { detail: "Permission denied" } },
    }),
  );

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function grants(list: Array<[string, string, string | null]>) {
  answer("authApi", "myPermissions", () =>
    Promise.resolve({
      is_superadmin: false,
      grants: list.map(([action, resource_type, resource_id]) => ({
        action,
        resource_type,
        resource_id,
      })),
    }),
  );
}

const { AliasesSubnetPanel, AddAddressModal, EditSubnetModal } =
  await import("./IPAMPage");
const { DHCPSubnetPanel } = await import("../dhcp/DHCPSubnetPanel");

describe("DHCP scope list refused (#4347)", () => {
  it("the DHCP Pools tab does not say the subnet has no scope", async () => {
    grants([["write", "subnet", "sub-1"]]);
    answer("dhcpApi", "listScopesBySubnet", refused);
    open(<DHCPSubnetPanel subnetId="sub-1" />);
    expect(
      await screen.findByText(/permission to see this subnet's DHCP scopes/),
    ).toBeTruthy();
    expect(screen.queryByText("No DHCP scopes on this subnet")).toBeNull();
  });

  it("an answered empty list still says there is none", async () => {
    grants([["read", "dhcp_scope", null]]);
    answer("dhcpApi", "listScopesBySubnet", () => Promise.resolve([]));
    open(<DHCPSubnetPanel subnetId="sub-1" />);
    expect(
      await screen.findByText("No DHCP scopes on this subnet"),
    ).toBeTruthy();
  });

  it("Allocate IP does not send the user to create a scope", async () => {
    grants([["write", "subnet", "sub-1"]]);
    answer("dhcpApi", "listScopesBySubnet", refused);
    answer("ipamApi", "getSubnet", () =>
      Promise.resolve({ id: "sub-1", network: "10.0.0.0/24" }),
    );
    open(<AddAddressModal subnetId="sub-1" onClose={() => {}} />);
    const status = (await screen.findAllByRole("combobox")).find((el) =>
      Array.from((el as HTMLSelectElement).options).some(
        (o) => o.value === "static_dhcp",
      ),
    ) as HTMLSelectElement;
    fireEvent.change(status, { target: { value: "static_dhcp" } });
    expect(
      await screen.findByText(/permission to see this subnet's DHCP scopes/),
    ).toBeTruthy();
    expect(screen.queryByText(/No DHCP scope exists/)).toBeNull();
    expect(screen.queryByText("Create a scope")).toBeNull();
  });
});

describe("Edit Subnet DDNS tab with the effective read refused (#4348)", () => {
  const subnet = {
    id: "sub-1",
    space_id: "sp-1",
    block_id: "b-1",
    network: "10.0.0.0/24",
    name: "x",
    ddns_inherit_settings: true,
    ddns_enabled: false,
  } as never;

  it("does not draw DDNS as off", async () => {
    grants([
      ["read", "subnet", "sub-1"],
      ["write", "subnet", "sub-1"],
    ]);
    answer("ipamApi", "getSubnet", () => Promise.resolve(subnet));
    answer("ipamApi", "getEffectiveSubnetDdns", refused);
    open(<EditSubnetModal subnet={subnet} onClose={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /DDNS/ }));
    expect(
      await screen.findByText(
        "The parent's DDNS settings are not visible to your role.",
      ),
    ).toBeTruthy();
    expect(
      screen.queryByText("Inheriting from the parent block or space."),
    ).toBeNull();
  });
});

describe("Aliases tab delete (#4349)", () => {
  const ALIAS = {
    id: "al-1",
    ip_address_id: "ip-1",
    fqdn: "www.example.com",
    record_type: "CNAME",
    value: "h.example.com",
    ip_address: "10.0.0.5",
    ip_hostname: "h",
  };

  async function row() {
    answer("ipamApi", "listSubnetAliases", () => Promise.resolve([ALIAS]));
    open(<AliasesSubnetPanel subnetId="sub-1" />);
    return (await screen.findByLabelText("Delete alias")) as HTMLButtonElement;
  }

  it("is disabled for a subnet writer", async () => {
    grants([
      ["read", "subnet", "sub-1"],
      ["write", "subnet", "sub-1"],
    ]);
    expect((await row()).disabled).toBe(true);
  });

  it("is disabled for the Viewer", async () => {
    grants([["read", "*", null]]);
    expect((await row()).disabled).toBe(true);
  });

  it("is offered to a holder of delete on subnets", async () => {
    grants([["delete", "subnet", null]]);
    const b = await row();
    await vi.waitFor(() => expect(b.disabled).toBe(false));
  });
});
