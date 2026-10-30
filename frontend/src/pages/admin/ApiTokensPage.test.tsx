/**
 * @vitest-environment jsdom
 *
 * Re-enabling an inactive API token is superadmin-only and needs the
 * operator step-up. The page offers Re-enable only to a superadmin, asks for
 * the step-up before sending, and keeps Revoke a one-click action.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const list = vi.fn();
const update = vi.fn();
const myPermissions = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    apiTokensApi: { ...actual.apiTokensApi, list, update },
    authApi: { ...actual.authApi, myPermissions },
  };
});

const { ApiTokensPage } = await import("./ApiTokensPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function token(
  id: string,
  name: string,
  isActive: boolean,
  expiresAt: string | null = null,
) {
  return {
    id,
    name,
    description: "",
    prefix: "sddi_AbCdE",
    scope: "user",
    scopes: [],
    resource_grants: [],
    user_id: "u1",
    expires_at: expiresAt,
    last_used_at: null,
    is_active: isActive,
    created_at: "2026-10-01T00:00:00.000Z",
  };
}

async function show(superadmin: boolean) {
  myPermissions.mockResolvedValue({ is_superadmin: superadmin, grants: [] });
  list.mockResolvedValue([
    token("t-live", "live-token", true),
    token("t-dead", "dead-token", false),
  ]);
  update.mockResolvedValue(token("t-dead", "dead-token", true));
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <ApiTokensPage />
    </QueryClientProvider>,
  );
  await screen.findByText("dead-token");
  await act(async () => {});
}

describe("API token Re-enable", () => {
  it("is not offered to a user who is not a superadmin", async () => {
    await show(false);
    expect(screen.queryByTitle("Re-enable")).toBeNull();
    // Revoking their own token stays available.
    expect(screen.getByTitle("Revoke")).toBeTruthy();
  });

  it("asks a superadmin for the step-up and sends it", async () => {
    await show(true);
    fireEvent.click(screen.getByTitle("Re-enable"));
    expect(update).not.toHaveBeenCalled();
    const submit = screen.getByRole("button", { name: "Re-enable token" });
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText(/Password/), {
      target: { value: "pw" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Re-enable token" }));
    await waitFor(() => expect(update).toHaveBeenCalled());
    expect(update).toHaveBeenCalledWith("t-dead", {
      is_active: true,
      stepup_password: "pw",
      stepup_totp_code: null,
    });
  });

  it("does not offer Re-enable on an expired token", async () => {
    myPermissions.mockResolvedValue({ is_superadmin: true, grants: [] });
    list.mockResolvedValue([
      token("t-exp", "expired-token", false, "2020-01-01T00:00:00.000Z"),
    ]);
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <ApiTokensPage />
      </QueryClientProvider>,
    );
    await screen.findByText("expired-token");
    await act(async () => {});
    expect(screen.queryByTitle("Re-enable")).toBeNull();
    const btn = screen.getByTitle(/Expired/) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
  });

  it("revokes without a step-up", async () => {
    await show(false);
    fireEvent.click(screen.getByTitle("Revoke"));
    await waitFor(() => expect(update).toHaveBeenCalled());
    expect(update).toHaveBeenCalledWith("t-live", { is_active: false });
  });
});
