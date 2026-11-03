/**
 * @vitest-environment jsdom
 *
 * #3429: PUT /settings admits a user with `write` on `settings`, so the page
 * must offer Save to them instead of "View-only — superadmin required".
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

let grants: { action: string; resource_type: string; resource_id: null }[] = [];
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
      get: async () => ({ app_title: "SpatiumDDI" }),
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
    renderPage();
    expect(await screen.findByRole("button", { name: /save/i })).toBeTruthy();
    expect(screen.queryByText(/superadmin required to edit/i)).toBeNull();
  });

  it("stays view-only without the grant", async () => {
    grants = [];
    renderPage();
    expect(await screen.findByText(/view-only/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /save/i })).toBeNull();
  });
});
