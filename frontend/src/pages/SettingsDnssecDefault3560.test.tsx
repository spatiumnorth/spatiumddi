/**
 * @vitest-environment jsdom
 *
 * The API refuses ``dns_default_dnssec_validation = yes`` (#3560): a new
 * group has no trust anchor, and BIND 9.20 will not load ``yes`` without
 * one. Settings keeps the option visible (so a default stored before the
 * refusal still displays) but not selectable, and says why.
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

describe("Default DNSSEC Validation (#3560)", () => {
  it("does not offer yes as a default, and says why", async () => {
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
      await screen.findByRole("button", { name: /^DNS Defaults/ }),
    );
    const select = (await screen.findByRole("combobox", {
      name: "Default DNSSEC Validation",
    })) as HTMLSelectElement;
    const yes = select.querySelector(
      'option[value="yes"]',
    ) as HTMLOptionElement;
    expect(yes.disabled).toBe(true);
    expect(select.querySelector('option[value="auto"]')).not.toBeNull();
    expect(screen.getByText(/will not load 'yes' without one/)).toBeTruthy();
  });
});
