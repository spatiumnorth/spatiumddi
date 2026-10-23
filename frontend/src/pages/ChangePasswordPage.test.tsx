/**
 * @vitest-environment jsdom
 *
 * Change Password — the wiring, not the arithmetic (#1004).
 *
 * `lib/password-policy.test.ts` pins that the rules evaluate correctly. That
 * was never the bug: the evaluation was right and the submit button ignored
 * it, so the page computed "this fails the 12-character rule", rendered the
 * row ungreen, and let the operator submit anyway. Only rendering the real
 * component catches a gate wired to the wrong expression — `tsc` is happy
 * either way, and so is a reviewer.
 *
 * This is the forced first-login screen, so every failure here lands on an
 * operator who cannot navigate away from it.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import type { PasswordPolicy } from "@/lib/api";

const navigate = vi.fn();
let locationState: unknown = null;
vi.mock("react-router-dom", () => ({
  useNavigate: () => navigate,
  useLocation: () => ({ state: locationState }),
  Link: ({ to, children }: { to: string; children: React.ReactNode }) => (
    <a href={to}>{children}</a>
  ),
}));

const changePassword = vi.fn();
const passwordPolicy = vi.fn();
vi.mock("@/lib/api", () => ({
  authApi: {
    changePassword: (...a: unknown[]) => changePassword(...a),
    passwordPolicy: () => passwordPolicy(),
  },
}));

// Thin stand-in: the page uses exactly one query and only its `data`.
vi.mock("@tanstack/react-query", () => ({
  useQuery: ({ queryFn }: { queryFn: () => unknown }) => ({ data: queryFn() }),
}));

const { ChangePasswordPage } = await import("./ChangePasswordPage");

const POLICY: PasswordPolicy = {
  min_length: 12,
  require_uppercase: true,
  require_lowercase: true,
  require_digit: true,
  require_symbol: false,
  history_count: 5,
  max_age_days: 0,
};

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

// `null` — not `undefined` — for "the policy has not loaded": a default
// parameter is applied when the argument IS undefined, so `setup(undefined)`
// would silently get POLICY and the test would assert nothing.
function setupVoluntary() {
  locationState = { voluntary: true };
  passwordPolicy.mockReturnValue(POLICY);
  render(<ChangePasswordPage />);
}

function setup(policy: PasswordPolicy | null = POLICY) {
  passwordPolicy.mockReturnValue(policy ?? undefined);
  render(<ChangePasswordPage />);
  const submit = screen.getByRole("button", {
    name: /set new password/i,
  }) as HTMLButtonElement;
  const type = (label: RegExp, value: string) =>
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  return { submit, type };
}

function fill(
  type: (l: RegExp, v: string) => void,
  current: string,
  next: string,
) {
  type(/^current password$/i, current);
  type(/^new password$/i, next);
  type(/^confirm new password$/i, next);
}

describe("submit gate", () => {
  it("refuses the issue's reproduction instead of round-tripping it", () => {
    // "Abcdef12" — 8 chars under a 12-char policy. Four rows green, button
    // enabled, server 400. The browser already knew.
    const { submit, type } = setup();
    fill(type, "old", "Abcdef12");
    expect(submit.disabled).toBe(true);
    fireEvent.click(submit);
    expect(changePassword).not.toHaveBeenCalled();
  });

  it("allows a password that meets every checkable rule", async () => {
    changePassword.mockResolvedValue(undefined);
    const { submit, type } = setup();
    fill(type, "old", "Abcdefghij12");
    expect(submit.disabled).toBe(false);
    fireEvent.click(submit);
    await waitFor(() =>
      expect(changePassword).toHaveBeenCalledWith("old", "Abcdefghij12"),
    );
  });

  it("still refuses a mismatched confirmation", () => {
    const { submit, type } = setup();
    type(/^current password$/i, "old");
    type(/^new password$/i, "Abcdefghij12");
    type(/^confirm new password$/i, "Abcdefghij13");
    expect(submit.disabled).toBe(true);
  });

  it("stays enabled while the policy has not loaded", () => {
    // Nothing to gate on, and the server is the authority regardless.
    // Disabling here would wedge the one screen the operator cannot leave.
    const { submit, type } = setup(null);
    fill(type, "old", "x");
    expect(submit.disabled).toBe(false);
  });
});

describe("rule list", () => {
  it("renders history as a note, with no tick of its own", () => {
    const { type } = setup();
    type(/^new password$/i, "x");
    const note = screen.getByText(/last 5 passwords/i);
    // A ✓ here is what made an 8-character password read as 4-of-5 done.
    expect(note.textContent).not.toMatch(/[✓○]/);
    expect(note.tagName).toBe("P");
  });

  it("ticks a rule as it starts passing", () => {
    const { type } = setup();
    type(/^new password$/i, "abcdefghijkl");
    expect(screen.getByText(/At least 12 characters/).textContent).toContain(
      "✓",
    );
    expect(screen.getByText(/uppercase/).textContent).toContain("○");
  });

  it("shows the operator's configured minimum, never a hardcoded 8", () => {
    setup({ ...POLICY, min_length: 20 });
    expect(screen.getByText(/At least 20 characters/)).toBeTruthy();
    expect(screen.queryByText(/8 characters/)).toBeNull();
  });
});

describe("server errors", () => {
  const axiosError = (detail: unknown) => ({
    isAxiosError: true,
    response: { data: { detail } },
  });

  it("puts a pydantic 422 array under the new-password field", async () => {
    // The shape that used to fall through to "Check your current password
    // and try again" — pointing at the wrong field entirely.
    changePassword.mockRejectedValue(
      axiosError([
        {
          type: "value_error",
          loc: ["body", "new_password"],
          msg: "Value error, Password cannot be empty",
        },
      ]),
    );
    const { submit, type } = setup();
    fill(type, "old", "Abcdefghij12");
    fireEvent.click(submit);
    await screen.findByText("Password cannot be empty");
    expect(screen.queryByText(/check your current password/i)).toBeNull();
  });

  it("still surfaces the policy 400's per-rule list", async () => {
    changePassword.mockRejectedValue(
      axiosError({
        reason: "password_policy",
        errors: ["Password must be at least 12 characters"],
      }),
    );
    const { submit, type } = setup();
    fill(type, "old", "Abcdefghij12");
    fireEvent.click(submit);
    await screen.findByText("Password must be at least 12 characters");
  });

  it("still surfaces a plain string detail", async () => {
    changePassword.mockRejectedValue(
      axiosError("Current password is incorrect"),
    );
    const { submit, type } = setup();
    fill(type, "wrong", "Abcdefghij12");
    fireEvent.click(submit);
    await screen.findByText("Current password is incorrect");
  });
});

describe("opened from Account (#2441)", () => {
  afterEach(() => {
    locationState = null;
  });

  it("does not claim the change is required, and offers a way back", () => {
    setupVoluntary();
    expect(screen.queryByText(/you must set a new password/i)).toBeNull();
    const cancel = screen.getByRole("link", { name: /cancel/i });
    expect(cancel.getAttribute("href")).toBe("/account");
  });

  it("keeps the required wording, and no way out, for a forced change", () => {
    setup();
    expect(screen.getByText(/you must set a new password/i)).toBeTruthy();
    expect(screen.queryByRole("link", { name: /cancel/i })).toBeNull();
  });
});
