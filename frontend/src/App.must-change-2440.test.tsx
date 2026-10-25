/**
 * @vitest-environment jsdom
 *
 * A user who must change their password is sent to /change-password by any
 * protected route, on a reload or a typed URL as on the login form (#2440).
 * Before, only the login form redirected; the console rendered with every
 * read refused ("Password change required before continuing").
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  render,
  renderHook,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter, Outlet, useLocation } from "react-router-dom";

let mustChange = true;
vi.mock("@/hooks/useAuth", () => ({
  useAuth: () => ({
    isAuthenticated: true,
    bootstrapping: false,
    mustChangePassword: mustChange,
  }),
}));
vi.mock("@/hooks/usePublicSettings", async () => ({
  ...(await vi.importActual<object>("@/hooks/usePublicSettings")),
  useBrandDocumentTitle: () => undefined,
}));
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true }),
}));
function Where() {
  return <span data-testid="location">{useLocation().pathname}</span>;
}
vi.mock("@/components/layout/AppLayout", () => ({
  AppLayout: () => (
    <div data-testid="app-chrome">
      <Where />
      <Outlet />
    </div>
  ),
}));
vi.mock("@/pages/ChangePasswordPage", () => ({
  ChangePasswordPage: () => (
    <div data-testid="change-password">
      <Where />
    </div>
  ),
}));

const { default: App } = await import("./App");

afterEach(() => {
  cleanup();
  mustChange = true;
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

describe("must-change-password users", () => {
  it.each(["/dashboard", "/admin/users", "/ipam"])(
    "a typed %s lands on Change Password, not the console",
    (path) => {
      renderAt(path);
      expect(screen.getByTestId("change-password")).toBeTruthy();
      expect(screen.queryByTestId("app-chrome")).toBeNull();
    },
  );

  it("a user who need not change still gets the console", () => {
    mustChange = false;
    renderAt("/definitely/not/a/page");
    expect(screen.getByTestId("app-chrome")).toBeTruthy();
  });
});

describe("the flag the route guard reads", () => {
  it("is learned from the boot refresh and cleared on sign-out", async () => {
    vi.resetModules();
    vi.doUnmock("@/hooks/useAuth");
    vi.doMock("@/lib/api", async () => ({
      ...(await vi.importActual<object>("@/lib/api")),
      authApi: {
        refresh: () =>
          Promise.resolve({
            access_token: "tok",
            token_type: "bearer",
            force_password_change: true,
          }),
        logout: () => Promise.resolve(),
      },
    }));
    const { useAuth } = await import("@/hooks/useAuth");
    const { result } = renderHook(() => useAuth());
    await waitFor(() => expect(result.current.isAuthenticated).toBe(true));
    expect(result.current.mustChangePassword).toBe(true);
    await act(async () => {
      await result.current.logout();
    });
    expect(result.current.mustChangePassword).toBe(false);
  });
});
