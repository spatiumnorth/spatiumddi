/**
 * @vitest-environment jsdom
 *
 * Re-enabling an inactive API token is superadmin-only and needs the
 * operator step-up. The page offers Re-enable only to a superadmin, asks for
 * the step-up before sending, and asks before Revoke (#4212).
 */
import { isIdleToken } from "@/lib/apiTokenIdle";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const list = vi.fn();
const update = vi.fn();
const create = vi.fn();
const myPermissions = vi.fn();
const usage = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    apiTokensApi: { ...actual.apiTokensApi, list, update, create, usage },
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
  ownerIsActive: boolean | null = true,
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
    owner_is_active: ownerIsActive,
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
    // #4212 — Revoke asks first.
    fireEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "Revoke",
      }),
    );
    await waitFor(() => expect(update).toHaveBeenCalled());
    expect(update).toHaveBeenCalledWith("t-live", { is_active: false });
  });
});

describe("API token of a disabled owner (#3431)", () => {
  async function showDisabledOwner(isActive: boolean) {
    myPermissions.mockResolvedValue({ is_superadmin: true, grants: [] });
    list.mockResolvedValue([
      token("t-x", "orphan-token", isActive, null, false),
    ]);
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <ApiTokensPage />
      </QueryClientProvider>,
    );
    await screen.findByText("orphan-token");
    await act(async () => {});
  }

  it("is not labelled Active", async () => {
    await showDisabledOwner(true);
    expect(screen.getByText("Owner disabled")).toBeTruthy();
    expect(screen.queryByText("Active")).toBeNull();
  });

  it("disables Re-enable and says why", async () => {
    await showDisabledOwner(false);
    expect(screen.queryByTitle("Re-enable")).toBeNull();
    const btn = screen.getByTitle(
      /owner account is disabled/,
    ) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
  });
});

describe("New token dialog focus (#3483)", () => {
  it("returns focus to New Token after Enter creates the token and the reveal closes", async () => {
    await show(true);
    create.mockResolvedValue({
      ...token("t-new", "ci-token", true),
      token: "sddi_secret",
    });
    const opener = screen.getByRole("button", { name: /New Token/ });
    opener.focus();
    fireEvent.click(opener);
    fireEvent.change(screen.getByPlaceholderText(/ansible-automation/), {
      target: { value: "ci-token" },
    });
    const pw = screen.getByLabelText(/Password/);
    fireEvent.change(pw, { target: { value: "pw" } });
    // Enter in the step-up field submits the form while the field keeps focus.
    pw.focus();
    fireEvent.submit(pw.closest("form") as HTMLFormElement);
    await waitFor(() => expect(create).toHaveBeenCalled());
    await waitFor(() => expect(screen.queryByText("New API Token")).toBeNull());
    fireEvent.keyDown(document, { key: "Escape" });
    fireEvent.click(
      await screen.findByRole("button", { name: "Close without copying" }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.activeElement).toBe(opener);
  });

  it("returns focus to New Token when the keyboard does it all: Enter in the password field, Esc, Close without copying", async () => {
    const user = userEvent.setup();
    await show(true);
    create.mockResolvedValue({
      ...token("t-new", "ci-token", true),
      token: "sddi_secret",
    });
    const opener = screen.getByRole("button", { name: /New Token/ });
    opener.focus();
    await user.keyboard("{Enter}");
    await user.type(
      screen.getByPlaceholderText(/ansible-automation/),
      "ci-token",
    );
    await user.type(screen.getByLabelText(/Password/), "pw{Enter}");
    await waitFor(() => expect(create).toHaveBeenCalled());
    await waitFor(() => expect(screen.queryByText("New API Token")).toBeNull());
    await user.keyboard("{Escape}");
    const discard = await screen.findByRole("button", {
      name: "Close without copying",
    });
    discard.focus();
    await user.keyboard("{Enter}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.activeElement).toBe(opener);
  });
});

describe("API token whose owner must change password (#3784)", () => {
  async function showBlocked(isActive: boolean) {
    myPermissions.mockResolvedValue({ is_superadmin: true, grants: [] });
    list.mockResolvedValue([
      {
        ...token("t-pw", "pw-token", isActive),
        owner_password_change_required: true,
        blocked_reason: "The owner must change their password",
      },
    ]);
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <ApiTokensPage />
      </QueryClientProvider>,
    );
    await screen.findByText("pw-token");
    await act(async () => {});
  }

  it("is not labelled Active", async () => {
    await showBlocked(true);
    expect(screen.getByText(/password change required/)).toBeTruthy();
    expect(screen.queryByText("Active")).toBeNull();
  });

  it("Re-enable does not promise immediate authentication", async () => {
    await showBlocked(false);
    fireEvent.click(screen.getByTitle("Re-enable"));
    expect(screen.queryByText(/starts authenticating again/)).toBeNull();
    expect(screen.getByText(/keep being refused/)).toBeTruthy();
  });
});

describe("Delete API Token refusal (#3822)", () => {
  it("says why in the dialog and re-reads the list", async () => {
    const remove = vi.fn().mockRejectedValue(
      Object.assign(new Error("404"), {
        response: { status: 404, data: { detail: "Token not found" } },
      }),
    );
    const { apiTokensApi } = await import("@/lib/api");
    apiTokensApi.delete = remove;
    await show(false);
    fireEvent.click(screen.getAllByTitle("Delete")[0]);
    const calls = list.mock.calls.length;
    const btns = await screen.findAllByRole("button", { name: "Delete" });
    fireEvent.click(btns[btns.length - 1]);
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain(
        "Token not found",
      ),
    );
    await waitFor(() => expect(list.mock.calls.length).toBeGreaterThan(calls));
  });
});

describe("API token usage and idle filter (#4491)", () => {
  it("classifies idle tokens, counting a never-used one from creation", () => {
    const now = Date.parse("2026-11-19T00:00:00Z");
    expect(
      isIdleToken(
        { last_used_at: "2026-11-18T00:00:00Z", created_at: "2026-01-01Z" },
        90,
        now,
      ),
    ).toBe(false);
    expect(
      isIdleToken(
        { last_used_at: "2026-01-01T00:00:00Z", created_at: "2025-01-01Z" },
        90,
        now,
      ),
    ).toBe(true);
    expect(
      isIdleToken(
        { last_used_at: null, created_at: "2026-11-10T00:00:00Z" },
        90,
        now,
      ),
    ).toBe(false);
    expect(
      isIdleToken(
        { last_used_at: null, created_at: "2026-01-01T00:00:00Z" },
        90,
        now,
      ),
    ).toBe(true);
  });

  it("shows the last client address and call count, and filters idle", async () => {
    myPermissions.mockResolvedValue({ is_superadmin: true, grants: [] });
    list.mockResolvedValue([
      {
        ...token("t-busy", "busy-token", true),
        last_used_at: new Date().toISOString(),
        last_client_ip: "198.51.100.4",
        calls_30d: 1234,
      },
      {
        ...token("t-old", "old-token", true),
        created_at: "2025-01-01T00:00:00Z",
      },
    ]);
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <ApiTokensPage />
      </QueryClientProvider>,
    );
    await screen.findByText("busy-token");
    expect(screen.getByText("198.51.100.4")).toBeTruthy();
    expect(screen.getByText(/1,234 calls/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/Idle only/));
    expect(screen.queryByText("busy-token")).toBeNull();
    expect(screen.getByText("old-token")).toBeTruthy();
  });

  it("opens a per-token usage chart over the usage endpoint", async () => {
    myPermissions.mockResolvedValue({ is_superadmin: true, grants: [] });
    list.mockResolvedValue([token("t-busy", "busy-token", true)]);
    usage.mockResolvedValue({
      token_id: "t-busy",
      days: [
        { day: "2026-11-17", calls: 3 },
        { day: "2026-11-18", calls: 0 },
      ],
      total: 3,
      last_used_at: "2026-11-17T10:00:00Z",
      last_client_ip: "198.51.100.4",
    });
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <ApiTokensPage />
      </QueryClientProvider>,
    );
    await screen.findByText("busy-token");
    expect(usage).not.toHaveBeenCalled();
    fireEvent.click(screen.getByTitle("Usage"));
    await waitFor(() => expect(usage).toHaveBeenCalledWith("t-busy", 30));
    expect((await screen.findByTestId("usage-total")).textContent).toContain(
      "3 calls in the last 30 days",
    );
    fireEvent.click(screen.getByRole("button", { name: "90d" }));
    await waitFor(() => expect(usage).toHaveBeenCalledWith("t-busy", 90));
  });
});
