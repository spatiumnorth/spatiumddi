/**
 * @vitest-environment jsdom
 *
 * The DNS group Records view's record delete offers Move to Trash or Delete
 * permanently, like the zone view (#4204 / #4078).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { DNSServerGroup } from "@/lib/api";

const deleteRecord = vi.fn(async (..._a: unknown[]) => ({}));
const myPermissions = vi.fn();
const empty = () => Promise.resolve([]);

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: (...a: unknown[]) => myPermissions(...a),
    },
    dnsApi: {
      ...actual.dnsApi,
      listGroupRecords: async () => ({
        items: [
          {
            id: "rec-1",
            zone_id: "zone-1",
            zone_name: "sheet.test.",
            view_id: null,
            view_name: null,
            name: "www",
            fqdn: "www.sheet.test.",
            record_type: "A",
            value: "192.0.2.1",
            ttl: null,
            priority: null,
            weight: null,
            port: null,
            auto_generated: false,
            tailscale_tenant_id: null,
            pool_member_id: null,
          },
        ],
        total: 1,
        page: 1,
      }),
      listZones: empty,
      listViews: empty,
      deleteRecord: (...a: unknown[]) => deleteRecord(...a),
    },
  };
});

const { RecordsTab } = await import("./DNSPage");

afterEach(() => {
  cleanup();
  deleteRecord.mockClear();
});

async function openDelete(isSuper: boolean) {
  myPermissions.mockResolvedValue({
    is_superadmin: isSuper,
    grants: isSuper
      ? []
      : [
          { action: "read", resource_type: "*", resource_id: null },
          { action: "delete", resource_type: "dns_record", resource_id: null },
        ],
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <RecordsTab
          group={{ id: "g1", name: "edge" } as DNSServerGroup}
          onSelectZone={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByText("192.0.2.1");
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
  fireEvent.click(await screen.findByTitle(/^Delete/));
  await screen.findByText("Move to Trash (reversible)");
}

describe("group Records delete: Trash or permanently (#4204)", () => {
  it("Move to Trash is the soft call", async () => {
    await openDelete(true);
    fireEvent.click(screen.getByRole("button", { name: "Move to Trash" }));
    await waitFor(() => expect(deleteRecord).toHaveBeenCalled());
    expect(deleteRecord).toHaveBeenCalledWith("g1", "zone-1", "rec-1", {
      permanent: false,
    });
  });

  it("a superadmin's Delete Permanently sends permanent=true", async () => {
    await openDelete(true);
    fireEvent.click(screen.getByRole("button", { name: "Delete Permanently" }));
    await waitFor(() => expect(deleteRecord).toHaveBeenCalled());
    expect(deleteRecord).toHaveBeenCalledWith("g1", "zone-1", "rec-1", {
      permanent: true,
    });
  });

  it("a non-superadmin sees Move to Trash only", async () => {
    await openDelete(false);
    expect(screen.getByRole("button", { name: "Move to Trash" })).toBeTruthy();
    expect(
      screen.queryByRole("button", { name: "Delete Permanently" }),
    ).toBeNull();
  });
});
