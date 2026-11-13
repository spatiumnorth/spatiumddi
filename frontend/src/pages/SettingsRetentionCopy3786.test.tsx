/**
 * @vitest-environment jsdom
 *
 * Data Retention's copy names everything it governs (#3786): the Trash row
 * every kind the Trash holds, the description the E911 trail.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      me: async () => ({ is_superadmin: true }),
      myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    },
    settingsApi: {
      ...actual.settingsApi,
      get: async () => ({
        app_title: "SpatiumDDI",
        dns_default_dnssec_validation: "auto",
        delegate_writable_fields: [],
      }),
      getDefaults: async () => ({}),
    },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true, ready: true }),
}));

const { SettingsPage } = await import("./SettingsPage");

afterEach(cleanup);

describe("Data Retention copy (#3786)", () => {
  it("names every Trash kind and the E911 trail", async () => {
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <SettingsPage />
      </QueryClientProvider>,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /^Data Retention/ }),
    );
    expect(
      await screen.findByText(/E911 location-lookup trail\./),
    ).toBeTruthy();
    const trash = await screen.findByText(/stay restorable this long/);
    for (const kind of ["customers", "overlay networks", "services"]) {
      expect(trash.textContent).toContain(kind);
    }
  });
});
