/**
 * @vitest-environment jsdom
 *
 * Service accounts page (#2144): a superadmin manages accounts and mints
 * their tokens through the shared create + reveal flow; anyone else is
 * offered no control, since every route behind the page is superadmin-only.
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

const ACCOUNT = {
  id: "sa-1",
  username: "homeassistant",
  display_name: "Home Assistant on ha.lan",
  is_active: true,
  groups: [{ id: "g-1", name: "HA readers" }],
  active_token_count: 1,
  last_used_at: null,
  next_token_expiry: null,
  created_at: "2026-11-01T00:00:00.000Z",
};

const perms = { isSuperadmin: true };
const createToken = vi.fn();
const update = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    serviceAccountsApi: {
      list: () => Promise.resolve([ACCOUNT]),
      listTokens: () => Promise.resolve([]),
      createToken: (...a: unknown[]) => createToken(...a),
      update: (...a: unknown[]) => update(...a),
      create: vi.fn(),
      delete: vi.fn(),
    },
    groupsApi: {
      list: () =>
        Promise.resolve([
          {
            id: "g-1",
            name: "HA readers",
            description: "",
            auth_source: "local",
          },
        ]),
    },
  };
});

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => perms.isSuperadmin,
      isSuperadmin: perms.isSuperadmin,
      isLoading: false,
    }),
  };
});

const { ServiceAccountsPage } =
  await import("@/pages/admin/ServiceAccountsPage");

function renderPage() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <ServiceAccountsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  perms.isSuperadmin = true;
  createToken.mockReset();
  update.mockReset();
});
afterEach(cleanup);

describe("ServiceAccountsPage", () => {
  it("lists the account with its description and groups", async () => {
    renderPage();
    expect(await screen.findByText("homeassistant")).toBeTruthy();
    expect(screen.getByText("Home Assistant on ha.lan")).toBeTruthy();
    expect(screen.getByText("HA readers")).toBeTruthy();
    expect(screen.getByText("1 active")).toBeTruthy();
  });

  it("offers a non-superadmin no control", async () => {
    perms.isSuperadmin = false;
    renderPage();
    await screen.findByText("homeassistant");
    const controls = [
      screen.getByRole("button", { name: /New Service Account/ }),
      screen.getByLabelText("Tokens for homeassistant"),
      screen.getByLabelText("Edit homeassistant"),
      screen.getByLabelText("Disable homeassistant"),
      screen.getByLabelText("Delete homeassistant"),
    ];
    for (const c of controls) {
      expect((c as HTMLButtonElement).disabled).toBe(true);
    }
  });

  it("mints a token for the account and reveals it once", async () => {
    createToken.mockResolvedValue({
      id: "t-1",
      name: "ha",
      description: "",
      prefix: "sddi_AbCdE",
      scope: "user",
      scopes: [],
      user_id: "sa-1",
      owner_is_service_account: true,
      expires_at: null,
      last_used_at: null,
      is_active: true,
      created_at: "2026-11-01T00:00:00.000Z",
      token: "sddi_AbCdE-secret",
    });
    renderPage();
    fireEvent.click(await screen.findByLabelText("Tokens for homeassistant"));
    fireEvent.click(await screen.findByRole("button", { name: /New Token/ }));
    expect(screen.getByText(/carries that account's permissions/)).toBeTruthy();
    fireEvent.change(screen.getByPlaceholderText("e.g. ansible-automation"), {
      target: { value: "ha" },
    });
    const pw = document.querySelector(
      'input[type="password"]',
    ) as HTMLInputElement;
    fireEvent.change(pw, { target: { value: "my-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() => expect(createToken).toHaveBeenCalled());
    const [id, body] = createToken.mock.calls[0] as [
      string,
      Record<string, unknown>,
    ];
    expect(id).toBe("sa-1");
    expect(body.name).toBe("ha");
    expect(body.stepup_password).toBe("my-password");
    expect(await screen.findByText(/only time/)).toBeTruthy();
  });

  it("disabling asks first and says the tokens are revoked", async () => {
    update.mockResolvedValue({ ...ACCOUNT, is_active: false });
    renderPage();
    fireEvent.click(await screen.findByLabelText("Disable homeassistant"));
    expect(
      screen.getByText(/Every token it holds is revoked now/),
    ).toBeTruthy();
    expect(update).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Disable" }));
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith("sa-1", { is_active: false }),
    );
  });
});
