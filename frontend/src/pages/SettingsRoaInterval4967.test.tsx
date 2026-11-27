/**
 * @vitest-environment jsdom
 *
 * The RPKI ROA refresh interval is accepted by the API (and the task and
 * docs/PRIVACY.md) as 1-168 h; Settings used to say 1-24 h and cap the
 * number box at 24 (#4967).
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
        rpki_roa_refresh_interval_hours: 4,
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

describe("RPKI ROA refresh interval range (#4967)", () => {
  it("states 1-168 h and allows up to 168", async () => {
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
      await screen.findByRole("button", { name: /^ASN Refresh/ }),
    );
    const label = await screen.findByText("RPKI ROA refresh interval");
    const field = label.closest("div")?.parentElement as HTMLElement;
    const input = (await screen.findByDisplayValue("4")) as HTMLInputElement;
    expect(input.max).toBe("168");
    expect(input.min).toBe("1");
    expect(field.textContent).toContain("1–168 h range");
    expect(field.textContent).not.toContain("24 h");
    expect(field.textContent).not.toContain("below 1 h");
  });
});
