/**
 * @vitest-environment jsdom
 *
 * DNS Blocklists offers its writes to exactly the callers the server lets
 * make them (#2698). The router takes `require_resource_permission("dnsbl")`
 * (write for pin / enable / sweep settings, delete for unpin and deleting a
 * list), so the built-in Network Editor (admin on `dnsbl`) gets every control
 * and a read-only Viewer gets none of them, with the reason as a tooltip.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { MyPermissions } from "@/lib/api";

const myPermissions = vi.fn<() => Promise<MyPermissions>>();

vi.mock("@/lib/api", () => ({
  authApi: { myPermissions: () => myPermissions() },
  dnsblApi: {
    listLists: () =>
      Promise.resolve([
        {
          id: "l1",
          name: "custom-list",
          zone_suffix: "bl.example",
          category: "spam",
          description: "",
          enabled: true,
          is_builtin: false,
          policy: null,
        },
      ]),
    listPinned: () =>
      Promise.resolve([
        { id: "p1", ip: "203.0.113.95", note: "probe", created_at: "" },
      ]),
    getSettings: () =>
      Promise.resolve({
        dnsbl_monitoring_enabled: true,
        dnsbl_check_interval_hours: 24,
        dnsbl_last_sweep_at: null,
      }),
    listListings: () => Promise.resolve({ items: [], total: 0 }),
  },
}));

const { DNSBLPage } = await import("./DNSBLPage");

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

function show(perms: MyPermissions) {
  myPermissions.mockResolvedValue(perms);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <DNSBLPage />
    </QueryClientProvider>,
  );
}

afterEach(() => cleanup());

const off = (el: HTMLElement) => (el as HTMLButtonElement).disabled;

describe("DNSBL page write gates (#2698)", () => {
  it("enables every write for the Network Editor", async () => {
    show(grants(["admin", "dnsbl"]));
    await screen.findByRole("button", { name: /Pin$/ });
    // (the Pin button itself stays disabled until an IP is typed)
    await waitFor(() =>
      expect(off(screen.getByPlaceholderText("203.0.113.5"))).toBe(false),
    );
    expect(off(screen.getByPlaceholderText("203.0.113.5"))).toBe(false);
    expect(off(screen.getByTitle("Unpin"))).toBe(false);
    expect(off(screen.getByTitle("Disable"))).toBe(false);
    expect(off(screen.getByTitle("Delete custom list"))).toBe(false);
    expect(off(screen.getByRole("switch", { name: /daily DNSBL sweep/ }))).toBe(
      false,
    );
  });

  it("disables every write for a Viewer, with the reason", async () => {
    show(grants(["read", "*"]));
    await screen.findByText("203.0.113.95");
    await waitFor(() => expect(myPermissions).toHaveBeenCalled());
    const ip = screen.getByPlaceholderText("203.0.113.5");
    await waitFor(() => expect(ip.getAttribute("title")).toBeTruthy());
    expect(off(ip)).toBe(true);
    expect(ip.getAttribute("title")).toBe("Requires write on DNS blocklists");
    const del = screen.getAllByTitle("Requires delete on DNS blocklists");
    expect(del).toHaveLength(2);
    expect(del.every(off)).toBe(true);
    expect(screen.queryByTitle("Unpin")).toBeNull();
    const sw = screen.getByRole("switch", { name: /daily DNSBL sweep/ });
    expect(off(sw)).toBe(true);
    expect(sw.getAttribute("title")).toBe("Requires write on DNS blocklists");
  });

  it("splits write from delete", async () => {
    show(grants(["write", "dnsbl"], ["read", "dnsbl"]));
    await screen.findByRole("button", { name: /Pin$/ });
    await waitFor(() =>
      expect(off(screen.getByPlaceholderText("203.0.113.5"))).toBe(false),
    );
    expect(
      screen.getAllByTitle("Requires delete on DNS blocklists"),
    ).toHaveLength(2);
  });
});
