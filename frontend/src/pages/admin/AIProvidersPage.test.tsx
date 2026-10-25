/**
 * @vitest-environment jsdom
 *
 * A read-only user is not offered New provider (the routes are
 * superadmin-only) and is not told "No providers configured" over a refused
 * list read (#2525).
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
import { MemoryRouter } from "react-router-dom";

const state: { superadmin: boolean; refused: boolean; hasKey: boolean | null } =
  {
    superadmin: false,
    refused: true,
    hasKey: null,
  };
const updateProvider = vi.fn().mockResolvedValue({});
const provider = (hasKey: boolean) => ({
  id: "p1",
  name: "local",
  kind: "openai_compat",
  base_url: "http://192.0.2.1:11434/v1",
  has_api_key: hasKey,
  default_model: "m",
  is_enabled: false,
  priority: 100,
  options: {},
  system_prompt_override: null,
  enabled_tools: null,
  created_at: "2026-10-23T00:00:00Z",
  modified_at: "2026-10-23T00:00:00Z",
});

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
          : state.hasKey === null
            ? []
            : [provider(state.hasKey)],
      updateProvider: (id: string, body: unknown) => updateProvider(id, body),
      getDefaultSystemPrompt: async () => "",
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
afterEach(() => {
  cleanup();
  state.hasKey = null;
});

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

describe("Edit AI provider's API key (#2622)", () => {
  async function openEdit(hasKey: boolean) {
    state.superadmin = true;
    state.refused = false;
    state.hasKey = hasKey;
    updateProvider.mockClear();
    renderPage();
    fireEvent.click(await screen.findByLabelText("Edit provider"));
    await screen.findByText(/API key/);
  }

  it("offers a Remove control that sends api_key '' and keeps the key otherwise", async () => {
    await openEdit(true);
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/clear to remove/i);
    expect(text).toMatch(/a key is stored/);
    // Saved untouched: the key is not sent, so it is kept.
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateProvider).toHaveBeenCalledTimes(1));
    expect(updateProvider.mock.calls[0][1]).not.toHaveProperty("api_key");
    cleanup();
    await openEdit(true);
    fireEvent.click(screen.getByLabelText("Remove the stored key"));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateProvider).toHaveBeenCalledTimes(1));
    expect(updateProvider.mock.calls[0][1].api_key).toBe("");
  });

  it("says nothing is stored, and offers no Remove, for a provider with no key", async () => {
    await openEdit(false);
    expect(document.body.textContent).toMatch(/no key stored/);
    expect(screen.queryByLabelText("Remove the stored key")).toBeNull();
  });
});
