/**
 * @vitest-environment jsdom
 *
 * New User and Reset password say a password-policy refusal in words
 * (#3040). The API answers 400 with `{reason: "password_policy", errors:
 * [...]}`; the dialogs used to print that object as raw JSON.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const USER = {
  id: "u-1",
  username: "someone",
  email: "someone@example.com",
  display_name: "Someone",
  is_active: true,
  is_superadmin: false,
  force_password_change: false,
  auth_source: "local",
  last_login_at: null,
};

const ERRORS = [
  "Password must be at least 12 characters",
  "Password must contain at least one uppercase letter",
];

function policyRefusal() {
  return Object.assign(new Error("Request failed with status code 400"), {
    isAxiosError: true,
    response: {
      status: 400,
      data: { detail: { reason: "password_policy", errors: ERRORS } },
    },
  });
}

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    usersApi: {
      list: () => Promise.resolve([USER]),
      create: () => Promise.reject(policyRefusal()),
      resetPassword: () => Promise.reject(policyRefusal()),
    },
    authProvidersApi: { list: () => Promise.resolve([]) },
  };
});

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

const { UsersPage } = await import("@/pages/admin/UsersPage");

function open() {
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

afterEach(cleanup);

function expectWordsNotJson() {
  const line = document.querySelector("p.text-destructive");
  expect(line).not.toBeNull();
  for (const e of ERRORS) expect(line!.textContent).toContain(e);
  expect(line!.textContent).not.toContain("{");
  expect(line!.textContent).not.toContain("password_policy");
}

describe("user dialogs, a refused password", () => {
  it("New User says the policy's errors in words", async () => {
    open();
    fireEvent.click(screen.getByRole("button", { name: /New User/ }));
    fireEvent.change(document.querySelectorAll("input")[0], {
      target: { value: "newbie" },
    });
    fireEvent.change(document.querySelector('input[type="email"]')!, {
      target: { value: "n@example.com" },
    });
    fireEvent.change(document.querySelector('input[type="password"]')!, {
      target: { value: "short" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(expectWordsNotJson);
  });

  it("Reset password says the policy's errors in words", async () => {
    open();
    fireEvent.click(await screen.findByTitle("Reset password"));
    const pw = document.querySelectorAll('input[type="password"]');
    fireEvent.change(pw[0], { target: { value: "short" } });
    fireEvent.change(pw[1], { target: { value: "short" } });
    fireEvent.click(screen.getByRole("button", { name: "Reset Password" }));
    await waitFor(expectWordsNotJson);
  });
});
