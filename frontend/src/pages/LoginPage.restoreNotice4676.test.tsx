/**
 * @vitest-environment jsdom
 *
 * The "Restore applied" notice reaches the sign-in page the operator lands
 * on (#4676). The 401 handler sets location.href = "/login", and before that
 * full load arrives the old page's protected-route redirect may mount a
 * LoginPage that is about to be thrown away. That mount must not eat the
 * note, and a reload of the real sign-in page must still show it.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import {
  RESTORE_IN_FLIGHT_KEY,
  RESTORE_NOTE_TTL_MS,
  markRestoreInFlight,
} from "@/lib/restoreInFlight";

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

const NOTICE = /restore/i;

beforeEach(() => sessionStorage.clear());
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("restore notice on the sign-in page (#4676)", () => {
  it("survives the old page's LoginPage mount and shows on the next one", () => {
    markRestoreInFlight();
    // The doomed mount from the old page's protected-route redirect.
    const first = render(<LoginPage />);
    first.unmount();
    expect(sessionStorage.getItem(RESTORE_IN_FLIGHT_KEY)).not.toBeNull();
    // The real /login load, and a reload of it.
    render(<LoginPage />);
    expect(screen.getByText(NOTICE)).toBeTruthy();
    cleanup();
    render(<LoginPage />);
    expect(screen.getByText(NOTICE)).toBeTruthy();
  });

  it("shows nothing without a note", () => {
    render(<LoginPage />);
    expect(screen.queryByText(NOTICE)).toBeNull();
  });

  it("does not show a stale note", () => {
    sessionStorage.setItem(
      RESTORE_IN_FLIGHT_KEY,
      String(Date.now() - RESTORE_NOTE_TTL_MS - 1000),
    );
    render(<LoginPage />);
    expect(screen.queryByText(NOTICE)).toBeNull();
  });

  it("is cleared by a successful sign-in", async () => {
    markRestoreInFlight();
    login.mockResolvedValue({
      mfa_required: false,
      force_password_change: false,
    });
    render(<LoginPage />);
    fireEvent.change(screen.getByLabelText(/username/i), {
      target: { value: "alice" },
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: "pw" },
    });
    fireEvent.submit(screen.getByLabelText(/password/i).closest("form")!);
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
    expect(sessionStorage.getItem(RESTORE_IN_FLIGHT_KEY)).toBeNull();
  });

  it("is kept by a failed sign-in", async () => {
    markRestoreInFlight();
    login.mockRejectedValue(new Error("bad"));
    render(<LoginPage />);
    fireEvent.change(screen.getByLabelText(/username/i), {
      target: { value: "alice" },
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: "pw" },
    });
    fireEvent.submit(screen.getByLabelText(/password/i).closest("form")!);
    await waitFor(() => expect(login).toHaveBeenCalled());
    expect(sessionStorage.getItem(RESTORE_IN_FLIGHT_KEY)).not.toBeNull();
  });
});
