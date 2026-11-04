/**
 * @vitest-environment jsdom
 *
 * Edit User says, before Save, that disabling revokes API tokens (#3432).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const USER = {
  id: "u-1",
  username: "someone",
  email: "someone@example.com",
  display_name: "Someone",
  is_active: true,
  is_superadmin: false,
  force_password_change: false,
  auth_source: "local",
  last_login_at: null,
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    usersApi: { list: () => Promise.resolve([USER]) },
    authProvidersApi: { list: () => Promise.resolve([]) },
  };
});

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

const { UsersPage } = await import("@/pages/admin/UsersPage");

afterEach(cleanup);

describe("Edit User, disabling", () => {
  it("warns that disabling revokes API tokens before Save", async () => {
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <MemoryRouter>
          <UsersPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByTitle("Edit"));
    expect(screen.getByText(/revokes its API tokens/)).toBeTruthy();
    expect(screen.getByText(/does not bring the tokens back/)).toBeTruthy();
  });
});
