/**
 * @vitest-environment jsdom
 *
 * #3429: PUT /settings admits a user with `write` on `settings`, so the page
 * must offer Save to them instead of "View-only — superadmin required".
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

let grants: { action: string; resource_type: string; resource_id: null }[] = [];
let delegable: string[] = [];
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      me: async () => ({ is_superadmin: false }),
      myPermissions: async () => ({ is_superadmin: false, grants }),
    },
    settingsApi: {
      ...actual.settingsApi,
      // The API serves its delegate allowlist (#3429); the page reads it
      // rather than keeping a copy.
      get: async () => ({
        app_title: "SpatiumDDI",
        ip_allocation_strategy: "sequential",
        delegate_writable_fields: delegable,
      }),
      getDefaults: async () => ({}),
    },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true, ready: true }),
}));

const { SettingsPage } = await import("./SettingsPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function renderPage() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <SettingsPage />
    </QueryClientProvider>,
  );
}

describe("Settings gate (#3429)", () => {
  it("shows Save to a user with write on settings", async () => {
    grants = [
      { action: "write", resource_type: "settings", resource_id: null },
    ];
    delegable = ["ip_allocation_strategy"];
    renderPage();
    expect(await screen.findByRole("button", { name: /save/i })).toBeTruthy();
    expect(screen.queryByText(/superadmin required to edit/i)).toBeNull();
    // A superadmin-only field stays locked for a delegate…
    const title = screen.getByRole("textbox", { name: "Application Title" });
    expect((title as HTMLInputElement).disabled).toBe(true);
    // …and a field the API lists in delegate_writable_fields is editable.
    fireEvent.click(screen.getByRole("button", { name: /^IP Allocation/ }));
    const strategy = await screen.findByRole("combobox", {
      name: "Allocation Strategy",
    });
    expect((strategy as HTMLSelectElement).disabled).toBe(false);
    // POST /settings/reverse-dns/run takes the same grant, so "Run now" is
    // offered to a delegate (its enable toggle stays superadmin-only).
    fireEvent.click(screen.getByRole("button", { name: /^Reverse DNS/ }));
    const run = await screen.findByRole("button", { name: "Run now" });
    expect((run as HTMLButtonElement).disabled).toBe(false);
  });

  it("enables only the fields the API lists for a delegate", async () => {
    // Same grant, but the API no longer delegates the allocation strategy:
    // the page follows the served list, not a copy of its own.
    grants = [
      { action: "write", resource_type: "settings", resource_id: null },
    ];
    delegable = ["dns_default_ttl"];
    renderPage();
    expect(await screen.findByRole("button", { name: /save/i })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /^IP Allocation/ }));
    const strategy = await screen.findByRole("combobox", {
      name: "Allocation Strategy",
    });
    expect((strategy as HTMLSelectElement).disabled).toBe(true);
  });

  it("stays view-only without the grant", async () => {
    grants = [];
    delegable = ["ip_allocation_strategy"];
    renderPage();
    expect(await screen.findByText(/view-only/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /save/i })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /^IP Allocation/ }));
    const strategy = await screen.findByRole("combobox", {
      name: "Allocation Strategy",
    });
    expect((strategy as HTMLSelectElement).disabled).toBe(true);
  });
});
