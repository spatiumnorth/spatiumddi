/**
 * @vitest-environment jsdom
 *
 * New User and Edit User say a refused email in words (#2435). A 422's
 * detail is an array of field errors; the dialogs used to print it as raw
 * JSON.
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

function invalidEmail() {
  return Object.assign(new Error("Request failed with status code 422"), {
    isAxiosError: true,
    response: {
      status: 422,
      data: {
        detail: [
          {
            type: "value_error",
            loc: ["body", "email"],
            msg: "Value error, Invalid email address",
            input: "x@nodot",
            ctx: { error: {} },
          },
        ],
      },
    },
  });
}

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    usersApi: {
      list: () => Promise.resolve([USER]),
      create: () => Promise.reject(invalidEmail()),
      update: () => Promise.reject(invalidEmail()),
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
  expect(line!.textContent).toContain("Invalid email address");
  expect(line!.textContent).not.toContain("{");
  expect(line!.textContent).not.toContain("[");
  expect(line!.textContent).not.toContain("Value error");
}

describe("user dialogs, a refused email", () => {
  it("Edit User says it in words", async () => {
    open();
    fireEvent.click(await screen.findByTitle("Edit"));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(expectWordsNotJson);
  });

  it("New User says it in words", async () => {
    open();
    fireEvent.click(screen.getByRole("button", { name: /New User/ }));
    const inputs = document.querySelectorAll("input");
    fireEvent.change(inputs[0], { target: { value: "newbie" } });
    fireEvent.change(document.querySelector('input[type="email"]')!, {
      target: { value: "x@nodot" },
    });
    fireEvent.change(document.querySelector('input[type="password"]')!, {
      target: { value: "Some-Pass-1234!" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(expectWordsNotJson);
  });
});
