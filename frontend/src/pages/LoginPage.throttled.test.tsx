/**
 * @vitest-environment jsdom
 *
 * A throttled sign-in reads as throttled. The server answers 429 once the
 * per-source, per-username or install-wide sign-in budget is spent; showing
 * that as "Invalid username or password" sends the user back to retype a
 * password that may be right, which only extends the wait.
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

const navigate = vi.fn();
vi.mock("react-router-dom", () => ({
  useNavigate: () => navigate,
  useSearchParams: () => [new URLSearchParams(), vi.fn()],
}));

const login = vi.fn();
vi.mock("@/hooks/useAuth", () => ({
  useAuth: () => ({ login, completeMfa: vi.fn() }),
}));

vi.mock("@/lib/api", () => ({
  authApi: { publicProviders: () => Promise.resolve([]) },
}));

vi.mock("@/hooks/usePublicSettings", () => ({
  DEFAULT_APP_TITLE: "SpatiumDDI",
  usePublicSettings: () => ({
    settled: true,
    settings: {
      app_title: "",
      login_banner: { enabled: false, text: "", require_ack: false },
    },
  }),
}));
vi.mock("@/components/BrandLogo", () => ({ BrandLogo: () => null }));
vi.mock("@/components/layout/EnvironmentBanner", () => ({
  EnvironmentBanner: () => null,
}));

const { LoginPage } = await import("./LoginPage");

function submit() {
  render(<LoginPage />);
  fireEvent.change(screen.getByLabelText(/username/i), {
    target: { value: "alice" },
  });
  fireEvent.change(screen.getByLabelText(/password/i), {
    target: { value: "pw" },
  });
  fireEvent.submit(screen.getByLabelText(/password/i).closest("form")!);
}

afterEach(() => {
  cleanup();
  login.mockReset();
});

describe("LoginPage sign-in errors", () => {
  it("shows the server's message for a throttled sign-in", async () => {
    login.mockRejectedValue({
      response: {
        status: 429,
        data: { detail: "Too many login attempts. Try again shortly." },
      },
    });
    submit();
    await waitFor(() =>
      expect(screen.getByText(/too many login attempts/i)).toBeTruthy(),
    );
    expect(screen.queryByText(/invalid username or password/i)).toBeNull();
  });

  it("still reads a rejected password as invalid credentials", async () => {
    login.mockRejectedValue({
      response: { status: 401, data: { detail: "Invalid credentials" } },
    });
    submit();
    await waitFor(() =>
      expect(screen.getByText(/invalid username or password/i)).toBeTruthy(),
    );
  });
});

describe("LoginPage before sign-in (#2895)", () => {
  it("does not link to the About page", async () => {
    // The About page names the version, the libraries and the third-party
    // tools; it is for signed-in users, so nothing on the sign-in screen
    // points at it.
    const { container } = render(<LoginPage />);
    // Let the provider list settle, so the whole page is on screen.
    await act(async () => {});
    const hrefs = Array.from(container.querySelectorAll("a")).map((a) =>
      a.getAttribute("href"),
    );
    expect(hrefs.some((h) => h?.includes("/about"))).toBe(false);
    expect(hrefs.some((h) => h?.includes("/legal/"))).toBe(false);
    expect(screen.queryByText(/about/i)).toBeNull();
  });
});
