/**
 * @vitest-environment jsdom
 *
 * A read-only user is not offered New provider (the routes are
 * superadmin-only) and is not told "No providers configured" over a refused
 * list read (#2525).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const state: { superadmin: boolean; refused: boolean } = {
  superadmin: false,
  refused: true,
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: async () => ({
        is_superadmin: state.superadmin,
        grants: state.superadmin
          ? []
          : [{ action: "read", resource_type: "*", resource_id: null }],
      }),
    },
    aiApi: {
      ...actual.aiApi,
      listProviders: async () =>
        state.refused
          ? Promise.reject({
              response: {
                status: 403,
                data: { detail: "Superadmin required" },
              },
            })
          : [],
    },
  };
});

import { AIProvidersPage } from "./AIProvidersPage";

function renderPage() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <AIProvidersPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
afterEach(cleanup);

describe("AI Providers for a Viewer (#2525)", () => {
  it("says the list may not be seen, never that there are none", async () => {
    state.superadmin = false;
    state.refused = true;
    renderPage();
    await screen.findByText(/don't have permission to see AI providers/);
    expect(document.body.textContent).not.toContain("No providers configured");
  });

  it("disables New provider with its reason", async () => {
    state.superadmin = false;
    state.refused = true;
    renderPage();
    const btn = screen.getByRole("button", {
      name: /New provider/,
    }) as HTMLButtonElement;
    await vi.waitFor(() => expect(btn.disabled).toBe(true));
    expect(btn.title).toBe("Requires superadmin");
  });

  it("offers a superadmin New provider, and the empty text on a real empty list", async () => {
    state.superadmin = true;
    state.refused = false;
    renderPage();
    await screen.findByText(/No providers configured/);
    const btn = screen.getByRole("button", {
      name: /New provider/,
    }) as HTMLButtonElement;
    await vi.waitFor(() => expect(btn.disabled).toBe(false));
  });
});
