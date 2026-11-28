/**
 * @vitest-environment jsdom
 *
 * The AI prompt Edit dialog reads the prompt when it opens and sends only the
 * fields the operator changed (#4777).
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

const h = vi.hoisted(() => ({ reads: 0, update: vi.fn() }));
const base = {
  id: "p1",
  name: "Mine",
  description: "old description",
  prompt_text: "old text",
  is_shared: false,
  created_by_user_id: "u1",
  created_at: "2026-10-23T00:00:00Z",
  modified_at: "2026-10-23T00:00:00Z",
  is_owner: true,
};
const stored = { ...base, description: "changed elsewhere", is_shared: true };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    },
    aiApi: {
      ...actual.aiApi,
      listPrompts: async () => {
        h.reads += 1;
        return [h.reads === 1 ? base : stored];
      },
      updatePrompt: (...a: unknown[]) => {
        h.update(...a);
        return Promise.resolve(stored);
      },
    },
  };
});

import { AIPromptsPage } from "./AIPromptsPage";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  h.reads = 0;
});

describe("AI prompt Edit reads the row when it opens (#4777)", () => {
  it("shows what another client stored and Save sends only the name", async () => {
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
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    expect(await screen.findByDisplayValue("changed elsewhere")).toBeTruthy();
    fireEvent.change(screen.getByDisplayValue("Mine"), {
      target: { value: "Renamed" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^Save/ }));
    await waitFor(() => expect(h.update).toHaveBeenCalled());
    expect(h.update).toHaveBeenCalledWith("p1", { name: "Renamed" });
  });
});
