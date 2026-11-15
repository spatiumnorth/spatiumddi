/**
 * @vitest-environment jsdom
 *
 * Edit authentication provider saves only what changed (#4236).
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

const update = vi.fn();
const PROVIDER = {
  id: "ap1",
  name: "corp-radius",
  type: "radius",
  is_enabled: false,
  priority: 10,
  config: { host: "192.0.2.5", port: 1812 },
  has_secrets: true,
  auto_create_users: false,
  auto_update_users: false,
  mapping_count: 0,
  created_at: "2026-10-23T00:00:00Z",
  modified_at: "2026-10-23T00:00:00Z",
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      me: async () => ({ is_superadmin: true }),
    },
    authProvidersApi: {
      ...actual.authProvidersApi,
      list: async () => [PROVIDER],
      listMappings: async () => [],
      update: (id: string, body: unknown) => update(id, body),
    },
    groupsApi: { ...actual.groupsApi, list: async () => [] },
  };
});

const { AuthProvidersPage } = await import("./AuthProvidersPage");

afterEach(() => {
  cleanup();
  update.mockReset();
});

async function openEdit() {
  update.mockResolvedValue(PROVIDER);
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <AuthProvidersPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(await screen.findByTitle(/Edit/));
  await screen.findByDisplayValue("corp-radius");
}

describe("Edit auth provider saves only what changed (#4236)", () => {
  it("sends only the changed field", async () => {
    await openEdit();
    fireEvent.change(screen.getByDisplayValue("10"), {
      target: { value: "20" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update.mock.calls[0][1]).toEqual({ priority: 20 });
  });

  it("a Save with nothing changed sends nothing", async () => {
    await openEdit();
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Save" })).toBeNull(),
    );
    expect(update).not.toHaveBeenCalled();
  });
});
