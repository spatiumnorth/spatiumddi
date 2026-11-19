/**
 * @vitest-environment jsdom
 *
 * /about is a signed-in page (#2895). It names the version, the libraries
 * and the third-party tools, which someone probing the server from outside
 * must not learn, so it sits inside ProtectedRoute and inside the app chrome.
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

function Where() {
  const { pathname } = useLocation();
  return <span data-testid="location">{pathname}</span>;
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
vi.mock("@/pages/AboutPage", () => ({
  AboutPage: () => <p data-testid="about-page">about</p>,
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

describe("/about route (#2895)", () => {
  it("sends a signed-out visitor to /login without rendering the page", () => {
    authed = false;
    renderAt("/about");
    expect(screen.queryByTestId("about-page")).toBeNull();
    expect(screen.queryByTestId("app-chrome")).toBeNull();
    expect(screen.getByTestId("location").textContent).toBe("/login");
  });

  it("renders inside the app chrome for a signed-in user", () => {
    renderAt("/about");
    expect(screen.getByTestId("app-chrome")).toBeTruthy();
    expect(screen.getByTestId("about-page")).toBeTruthy();
    expect(screen.getByTestId("location").textContent).toBe("/about");
  });
});
