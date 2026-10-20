/**
 * @vitest-environment jsdom
 *
 * #2205: the Application title is bounded at 255 characters and a refused
 * save shows the API's reason, not the fixed "Failed to save settings".
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const update = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ is_superadmin: true }) },
    settingsApi: {
      ...actual.settingsApi,
      get: async () => ({ app_title: "SpatiumDDI" }),
      getDefaults: async () => ({}),
      update,
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

describe("Application title (#2205)", () => {
  it("caps the input at 255 and shows the API's reason on refusal", async () => {
    update.mockRejectedValue(
      Object.assign(new Error("Request failed with status code 422"), {
        response: {
          status: 422,
          data: { detail: "app_title must be 255 characters or fewer" },
        },
      }),
    );
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <SettingsPage />
      </QueryClientProvider>,
    );
    const input = (await screen.findByDisplayValue(
      "SpatiumDDI",
    )) as HTMLInputElement;
    expect(input.maxLength).toBe(255);
    fireEvent.change(input, { target: { value: "b" } });
    fireEvent.click(screen.getByRole("button", { name: /^Save/ }));
    await waitFor(() =>
      expect(
        screen.getByText("app_title must be 255 characters or fewer"),
      ).toBeTruthy(),
    );
    expect(screen.queryByText(/Failed to save settings/)).toBeNull();
  });
});
