/**
 * @vitest-environment jsdom
 *
 * Delete Server Group names what the delete destroys (#2607).
 *
 * The delete cascades to the group's MAC blocks, client classes, option
 * templates, PXE profiles, device policies and phone profiles (and its
 * responder / RA records), none of it into Trash. The dialog named only the
 * scopes already in Trash.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { DHCPServerGroup } from "@/lib/api";

const lists: Record<string, () => Promise<unknown[]>> = {};
const empty = () => Promise.resolve([]);

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pick = (k: string) => () => (lists[k] ?? empty)();
  return {
    ...actual,
    dhcpApi: {
      ...actual.dhcpApi,
      listServers: empty,
      listScopesByGroup: empty,
      listMacBlocks: pick("mac"),
      listClientClasses: pick("class"),
      listOptionTemplates: pick("template"),
      listPxeProfiles: pick("pxe"),
      listDevicePolicies: pick("policy"),
      listPhoneProfiles: pick("phone"),
    },
  };
});

const { DeleteServerGroupModal } = await import("./DHCPPage");

afterEach(() => {
  cleanup();
  for (const k of Object.keys(lists)) delete lists[k];
});

function open() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DeleteServerGroupModal
          group={{ id: "g1", name: "edge" } as DHCPServerGroup}
          onConfirm={() => {}}
          onClose={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const rows = (n: number) => () =>
  Promise.resolve(Array.from({ length: n }, () => ({})));

describe("Delete Server Group", () => {
  it("counts each kind of configuration the delete destroys", async () => {
    lists.mac = rows(2);
    lists.class = rows(1);
    lists.template = rows(3);
    lists.pxe = rows(1);
    lists.policy = rows(1);
    open();
    const said =
      (await screen.findByText(/Permanently delete group/)).textContent ?? "";
    expect(said).toMatch(/2 MAC blocks/);
    expect(said).toMatch(/1 client class\b/);
    expect(said).toMatch(/3 option templates/);
    expect(said).toMatch(/1 PXE profile\b/);
    expect(said).toMatch(/1 device policy\b/);
    expect(said).not.toMatch(/phone profile/);
    expect(said).toMatch(/none of it into Trash/);
    expect(said).toMatch(/responder and router-advertisement/);
  });

  it("names a kind it could not count, without a number", async () => {
    lists.mac = () => Promise.reject(new Error("403"));
    open();
    const said =
      (await screen.findByText(/Permanently delete group/)).textContent ?? "";
    expect(said).toMatch(/its MAC blocks/);
    expect(said).not.toMatch(/client class/);
  });

  it("adds no configuration clause for a group that holds none", async () => {
    open();
    const said =
      (await screen.findByText(/Permanently delete group/)).textContent ?? "";
    expect(said).not.toMatch(/own configuration/);
    expect(said).toMatch(/Scopes of this group already in Trash/);
  });
});
