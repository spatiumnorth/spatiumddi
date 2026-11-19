/**
 * @vitest-environment jsdom
 *
 * Every Trash route is superadmin-only, so a delete dialog that says
 * "can be restored from Administration → Trash" promises a way back to a
 * user the Trash refuses. The DNS bulk record delete and the customer
 * delete name who can restore, as the IPAM, zone and DHCP scope deletes do
 * (#3150, after #1930 and #2706).
 */
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const CUSTOMER = {
  id: "c1",
  name: "acme",
  account_number: null,
  status: "active",
  contact_email: null,
  contact_phone: null,
};

const rec = (id: string) => ({
  id,
  zone_id: "z1",
  view_id: null,
  name: id,
  fqdn: `${id}.example.com.`,
  record_type: "A",
  value: "192.0.2.1",
  ttl: null,
  priority: null,
  weight: null,
  port: null,
  auto_generated: false,
  tailscale_tenant_id: null,
  pool_member_id: null,
  created_at: "2026-10-31T00:00:00Z",
  modified_at: "2026-10-31T00:00:00Z",
});

const GRANTS = [
  { action: "delete", resource_type: "*", resource_id: null },
  { action: "write", resource_type: "*", resource_id: null },
  { action: "read", resource_type: "*", resource_id: null },
  { action: "admin", resource_type: "*", resource_id: null },
];

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
            get: (_t, method) => {
              if (typeof method === "symbol") return undefined;
              const k = `${name}.${String(method)}`;
              if (k === "customersApi.list")
                return async () => ({ items: [CUSTOMER], total: 1 });
              if (k === "dnsApi.listRecords")
                return async () => ({
                  items: [rec("a1"), rec("a2")],
                  total: 2,
                });
              if (k === "authApi.myPermissions")
                return async () => ({ is_superadmin: false, grants: GRANTS });
              return pending;
            },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { CustomersPage } = await import("@/pages/network/CustomersPage");
const { ZoneDetailView } = await import("@/pages/dns/DNSPage");

afterEach(cleanup);

const flat = (el: Element) => (el.textContent ?? "").replace(/\s+/g, " ");

async function show(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 100));
  });
}

function namesTheSuperadmin(said: string) {
  expect(said).toMatch(/Trash/);
  expect(said).toMatch(/superadmin can restore/i);
  expect(said).not.toMatch(/(?<!superadmin )can be restored/i);
}

describe("delete dialogs do not promise a Trash restore to everyone (#3150)", () => {
  it("customer row delete", async () => {
    await show(<CustomersPage />);
    fireEvent.click(await screen.findByTitle("Delete"));
    namesTheSuperadmin(
      flat(await screen.findByText(/Soft-delete customer "acme"/)),
    );
  });

  it("customer bulk delete", async () => {
    await show(<CustomersPage />);
    await screen.findByText("acme");
    fireEvent.click(screen.getAllByRole("checkbox")[1]);
    fireEvent.click(
      await screen.findByRole("button", { name: /Delete selected/ }),
    );
    namesTheSuperadmin(flat(await screen.findByText(/Soft-delete 1 customer/)));
  });

  it("DNS bulk record delete", async () => {
    await show(
      <ZoneDetailView
        group={{ id: "g1", name: "default", driver: "bind9" } as never}
        zone={
          {
            id: "z1",
            group_id: "g1",
            name: "example.com.",
            zone_type: "primary",
            view_id: null,
          } as never
        }
        onDeleted={() => {}}
      />,
    );
    const boxes = await screen.findAllByRole("checkbox");
    fireEvent.click(boxes[0]);
    fireEvent.click(
      await screen.findByRole("button", { name: /Delete selected/ }),
    );
    namesTheSuperadmin(flat(await screen.findByText(/selected records/)));
  });
});
