/**
 * @vitest-environment jsdom
 *
 * AI Prompts gates match the server (#3759): sharing is superadmin-only, and
 * a superadmin may edit / delete another user's prompt.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const state = { superadmin: false };
const row = (over: object) => ({
  id: "p1",
  name: "Other's prompt",
  description: "",
  prompt_text: "hi",
  is_shared: true,
  created_by_user_id: "u2",
  created_at: "2026-10-23T00:00:00Z",
  modified_at: "2026-10-23T00:00:00Z",
  is_owner: false,
  ...over,
});

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: async () => ({
        is_superadmin: state.superadmin,
        grants: [],
      }),
    },
    aiApi: { ...actual.aiApi, listPrompts: async () => [row({})] },
  };
});

import { AIPromptsPage } from "./AIPromptsPage";

function renderPage() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <AIPromptsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
afterEach(cleanup);

describe("AI Prompts gates (#3759)", () => {
  it("disables Share for a non-superadmin, named by its action only", async () => {
    state.superadmin = false;
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /New prompt/ }));
    const box = (await screen.findByRole("checkbox", {
      name: "Share with all users",
    })) as HTMLInputElement;
    expect(box.disabled).toBe(true);
    expect(box.getAttribute("aria-describedby")).toBeTruthy();
  });

  it("offers Share to a superadmin", async () => {
    state.superadmin = true;
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /New prompt/ }));
    const box = (await screen.findByRole("checkbox", {
      name: "Share with all users",
    })) as HTMLInputElement;
    await vi.waitFor(() => expect(box.disabled).toBe(false));
  });

  it("lets a superadmin edit and delete another user's prompt", async () => {
    state.superadmin = true;
    renderPage();
    await screen.findByText("Other's prompt");
    const edit = screen.getAllByTitle("Edit")[0] as HTMLButtonElement;
    await vi.waitFor(() => expect(edit.disabled).toBe(false));
    expect((screen.getByTitle("Delete") as HTMLButtonElement).disabled).toBe(
      false,
    );
  });

  it("keeps another user's prompt read-only for a non-superadmin", async () => {
    state.superadmin = false;
    renderPage();
    await screen.findByText("Other's prompt");
    // #3760 — a gated control keeps its action as its accessible name; the
    // refusal reason is in its title.
    const btns = screen.getAllByTitle(/Only the creator/);
    expect(btns).toHaveLength(2);
    btns.forEach((b) => expect((b as HTMLButtonElement).disabled).toBe(true));
    expect(btns.map((b) => b.getAttribute("aria-label")).sort()).toEqual([
      "Delete",
      "Edit",
    ]);
    expect(screen.queryByTitle("Edit")).toBeNull();
  });
});
