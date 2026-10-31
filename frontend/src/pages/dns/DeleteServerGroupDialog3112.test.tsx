/**
 * @vitest-environment jsdom
 *
 * DNS Delete Server Group names what the delete destroys (#3112): the
 * group's views, ACLs and TSIG keys go with it, none of it into Trash.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { DNSServerGroup } from "@/lib/api";

const lists: Record<string, () => Promise<unknown[]>> = {};
const empty = () => Promise.resolve([]);

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pick = (k: string) => () => (lists[k] ?? empty)();
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      listServers: empty,
      listZones: empty,
      listViews: pick("view"),
      listAcls: pick("acl"),
      listTSIGKeys: pick("key"),
    },
  };
});

const { DeleteDNSGroupModal } = await import("./DNSPage");

afterEach(() => {
  cleanup();
  for (const k of Object.keys(lists)) delete lists[k];
});

function open() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DeleteDNSGroupModal
          group={{ id: "g1", name: "edge" } as DNSServerGroup}
          onConfirm={() => {}}
          onClose={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const rows = (n: number) => () =>
  Promise.resolve(Array.from({ length: n }, () => ({})));

async function said(): Promise<string> {
  const el = await screen.findByText(/Permanently delete group/);
  return el.textContent ?? "";
}

describe("DNS Delete Server Group", () => {
  it("counts the views, ACLs and TSIG keys the delete destroys", async () => {
    lists.view = rows(2);
    lists.acl = rows(1);
    lists.key = rows(3);
    open();
    const text = await said();
    expect(text).toMatch(/2 views/);
    expect(text).toMatch(/1 ACL\b/);
    expect(text).toMatch(/3 TSIG keys/);
    expect(text).toMatch(/none of it into Trash/);
    expect(text).toMatch(/server options/);
  });

  it("names a kind it could not count, without a number", async () => {
    lists.view = () => Promise.reject(new Error("403"));
    open();
    const text = await said();
    expect(text).toMatch(/its views/);
    expect(text).not.toMatch(/TSIG key/);
  });

  it("adds no count clause for a group that holds none", async () => {
    open();
    const text = await said();
    expect(text).not.toMatch(/own configuration/);
    expect(text).toMatch(/Zones of this group already in Trash/);
  });

  it("the tick box names views, ACLs and TSIG keys", async () => {
    open();
    await said();
    fireEvent.click(screen.getByRole("button", { name: /^Continue$/ }));
    expect(
      await screen.findByText(/views, ACLs, TSIG keys and options/),
    ).toBeTruthy();
  });
});
