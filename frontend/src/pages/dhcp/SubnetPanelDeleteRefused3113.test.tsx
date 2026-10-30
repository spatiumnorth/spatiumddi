/**
 * @vitest-environment jsdom
 *
 * A refused pool or scope delete on the IPAM subnet's DHCP tab shows the
 * server's reason (#3113). Both answer 409 / 422 with a detail when a
 * Windows failover or split scope is involved, and the dialog used to stay
 * open with its first words and nothing else.
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

const POOL_DETAIL =
  "Refusing to remove the exclusion on 10.78.21.0/24: the split-scope halves would overlap.";
const SCOPE_DETAIL =
  "Scope 10.78.21.0/24 is in Windows failover relationship 'r1'; take it out of the relationship first.";

const deletePool = vi.fn(() =>
  Promise.reject({
    isAxiosError: true,
    response: { status: 422, data: { detail: POOL_DETAIL } },
  }),
);
const deleteScope = vi.fn(() =>
  Promise.reject({
    isAxiosError: true,
    response: { status: 409, data: { detail: SCOPE_DETAIL } },
  }),
);

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dhcpApi: {
      listScopesBySubnet: () =>
        Promise.resolve([
          {
            id: "scope-1",
            name: "staff",
            subnet_id: "sub-1",
            group_id: "grp-1",
            address_family: "ipv4",
            lease_time: 86400,
            enabled: true,
            ddns_enabled: false,
          },
        ]),
      listGroups: () => Promise.resolve([]),
      listStatics: () => Promise.resolve([]),
      listPools: () =>
        Promise.resolve([
          {
            id: "pool-1",
            name: "excl",
            start_ip: "10.78.21.10",
            end_ip: "10.78.21.20",
            pool_type: "excluded",
          },
        ]),
      deletePool: () => deletePool(),
      deleteScope: () => deleteScope(),
    },
  };
});
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return { ...actual, usePermissions: () => ({ can: () => true }) };
});
vi.mock("./WindowsFailoverPanel", () => ({ ScopeServingStrip: () => null }));
vi.mock("./CreateScopeModal", () => ({ CreateScopeModal: () => null }));
vi.mock("./CreatePoolModal", () => ({ CreatePoolModal: () => null }));

const { DHCPSubnetPanel } = await import("./DHCPSubnetPanel");
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

async function openPanel() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <DHCPSubnetPanel subnetId="sub-1" />
    </QueryClientProvider>,
  );
  await screen.findByText("10.78.21.10");
}

async function confirmDelete(trigger: string) {
  fireEvent.click(screen.getByTitle(trigger));
  // The modal mounts last, so its acknowledgement is the last checkbox.
  fireEvent.click((await screen.findAllByRole("checkbox")).pop() as Element);
  fireEvent.click(screen.getByRole("button", { name: "Delete" }));
}

describe("subnet DHCP tab delete refusals (#3113)", () => {
  it("shows why a pool delete was refused, and forgets it on reopen", async () => {
    await openPanel();
    await confirmDelete("Delete pool");
    expect(await screen.findByText(POOL_DETAIL)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByText(POOL_DETAIL)).toBeNull());
    fireEvent.click(screen.getByTitle("Delete pool"));
    await screen.findByRole("button", { name: "Delete" });
    expect(screen.queryByText(POOL_DETAIL)).toBeNull();
  });

  it("shows why a scope delete was refused", async () => {
    await openPanel();
    await confirmDelete("Delete scope");
    expect(await screen.findByText(SCOPE_DETAIL)).toBeTruthy();
  });
});
