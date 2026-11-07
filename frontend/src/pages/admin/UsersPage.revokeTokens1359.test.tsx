/**
 * @vitest-environment jsdom
 *
 * "Revoke all API tokens" on the Users page (#1359): offered to a superadmin
 * behind a confirmation; disabled with the reason for a role the server
 * refuses, and nothing is requested.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const USERS = [
  {
    id: "u-1",
    username: "someone",
    email: "someone@example.com",
    display_name: "Someone",
    is_active: true,
    is_superadmin: false,
    force_password_change: false,
    auth_source: "local",
    last_login_at: null,
    api_token_count: 2,
  },
  {
    id: "u-2",
    username: "notokens",
    email: "n@example.com",
    display_name: "N",
    is_active: true,
    is_superadmin: false,
    force_password_change: false,
    auth_source: "local",
    last_login_at: null,
    api_token_count: 0,
  },
];

const revokeApiTokens = vi.fn();
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    usersApi: {
      list: () => Promise.resolve(USERS),
      revokeApiTokens: (...a: unknown[]) => revokeApiTokens(...a),
    },
    authProvidersApi: { list: () => Promise.resolve([]) },
  };
});

let superadmin = true;
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => superadmin,
      isSuperadmin: superadmin,
      isLoading: false,
    }),
  };
});

const { UsersPage } = await import("@/pages/admin/UsersPage");

function renderPage() {
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
}

beforeEach(() => {
  revokeApiTokens.mockReset();
  revokeApiTokens.mockResolvedValue({
    api_tokens_revoked: 2,
    api_token_count: 0,
  });
});
afterEach(cleanup);

describe("Users, Revoke all API tokens", () => {
  it("is offered only to a user holding tokens, and revokes after confirming", async () => {
    superadmin = true;
    renderPage();
    const buttons = await screen.findAllByLabelText("Revoke all API tokens");
    expect(buttons).toHaveLength(1); // not on the user with none
    fireEvent.click(buttons[0]);
    expect(revokeApiTokens).not.toHaveBeenCalled(); // confirm first
    fireEvent.click(screen.getByRole("button", { name: "Revoke all" }));
    await waitFor(() => expect(revokeApiTokens).toHaveBeenCalledTimes(1));
    expect(revokeApiTokens.mock.calls[0][0]).toBe("u-1");
  });

  it("is disabled with the reason for a non-superadmin, and requests nothing", async () => {
    superadmin = false;
    renderPage();
    const button = (await screen.findByLabelText(
      "Revoke all API tokens",
    )) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.title).toBe("Requires superadmin");
    fireEvent.click(button);
    expect(screen.queryByRole("button", { name: "Revoke all" })).toBeNull();
    expect(revokeApiTokens).not.toHaveBeenCalled();
  });

  it("shows the server's refusal in the confirmation instead of failing silently", async () => {
    superadmin = true;
    revokeApiTokens.mockRejectedValue(
      Object.assign(new Error("Request failed with status code 409"), {
        isAxiosError: true,
        response: {
          status: 409,
          data: { detail: "Refused for a test reason" },
        },
      }),
    );
    renderPage();
    fireEvent.click(await screen.findByLabelText("Revoke all API tokens"));
    fireEvent.click(screen.getByRole("button", { name: "Revoke all" }));
    expect(await screen.findByText(/Refused for a test reason/)).toBeTruthy();
  });
});
