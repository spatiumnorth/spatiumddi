/**
 * @vitest-environment jsdom
 *
 * Route table — the catch-all (#1360).
 *
 * With no `path="*"`, an unknown URL matched nothing and `<Routes>`
 * rendered null: a blank page with no chrome, and — because
 * `ProtectedRoute` was never reached — no redirect to /login for a
 * signed-out user either. The fix is entirely about WHERE the catch-all
 * sits, which only rendering the real route table can check.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter, Outlet, useLocation } from "react-router-dom";

let authed = true;
vi.mock("@/hooks/useAuth", () => ({
  useAuth: () => ({ isAuthenticated: authed, bootstrapping: false }),
}));
vi.mock("@/hooks/usePublicSettings", async () => ({
  ...(await vi.importActual<object>("@/hooks/usePublicSettings")),
  useBrandDocumentTitle: () => undefined,
}));
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true }),
}));

// Stand-ins for the chrome and the pages a redirect lands on: the test is
// about which element the route table picks, not what those pages render.
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
vi.mock("@/pages/LoginPage", () => ({
  LoginPage: () => <Where />,
}));
vi.mock("@/pages/network/DeviceDetailView", () => ({
  DeviceDetailView: () => <p>device detail</p>,
}));

const { default: App } = await import("./App");

afterEach(() => {
  cleanup();
  authed = true;
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

describe("catch-all route", () => {
  it("renders the 404 page inside the app chrome", () => {
    renderAt("/definitely/not/a/page");
    expect(screen.getByTestId("app-chrome")).toBeTruthy();
    expect(
      screen.getByRole("heading", { name: /page not found/i }),
    ).toBeTruthy();
  });

  it("sends a signed-out user to /login instead", () => {
    authed = false;
    renderAt("/definitely/not/a/page");
    expect(screen.queryByTestId("app-chrome")).toBeNull();
    expect(screen.getByTestId("location").textContent).toBe("/login");
  });

  it("treats a /network/<typo> as a 404, not a device id", () => {
    renderAt("/network/vlna");
    expect(
      screen.getByRole("heading", { name: /page not found/i }),
    ).toBeTruthy();
    expect(screen.queryByText("device detail")).toBeNull();
  });

  it("still redirects a legacy /network/<uuid> bookmark", () => {
    const id = "3f2b8c1e-9a4d-4e7b-8c21-5d6f7a8b9c0d";
    renderAt(`/network/${id}`);
    expect(screen.getByText("device detail")).toBeTruthy();
    expect(screen.getByTestId("location").textContent).toBe(
      `/network/devices/${id}`,
    );
  });
});
