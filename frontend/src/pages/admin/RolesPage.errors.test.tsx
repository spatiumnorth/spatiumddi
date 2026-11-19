/**
 * @vitest-environment jsdom
 *
 * New Role and Clone say a blank-name refusal in words (#3041). A 422's
 * detail is an array of field errors; the dialogs used to print it as raw
 * JSON.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const VIEWER = {
  id: "role-v",
  name: "Viewer",
  description: "",
  is_builtin: true,
  permissions: [{ action: "read", resource_type: "*" }],
};

function blank(what: string) {
  return Object.assign(new Error("Request failed with status code 422"), {
    isAxiosError: true,
    response: {
      status: 422,
      data: {
        detail: [
          {
            type: "value_error",
            loc: ["body", "name"],
            msg: `Value error, ${what} name cannot be empty`,
            input: " ",
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
    rolesApi: {
      list: () => Promise.resolve([VIEWER]),
      create: () => Promise.reject(blank("Role")),
      clone: () => Promise.reject(blank("Clone")),
    },
    authApi: {
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    },
  };
});

const { RolesPage } = await import("@/pages/admin/RolesPage");

beforeEach(() => {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <RolesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
});

afterEach(cleanup);

function expectWordsNotJson(sentence: string) {
  const line = within(screen.getAllByRole("dialog").at(-1)!).getByText(
    (_, el) => el?.tagName === "P" && el.classList.contains("text-destructive"),
  );
  expect(line.textContent).toContain(sentence);
  expect(line.textContent).not.toMatch(/[{[]|Value error/);
}

describe("role dialogs, a blank name", () => {
  it("New Role says it in words", async () => {
    fireEvent.click(await screen.findByRole("button", { name: /New Role/ }));
    const dialog = screen.getAllByRole("dialog").at(-1)!;
    fireEvent.change(within(dialog).getAllByRole("textbox")[0], {
      target: { value: "   " },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: /^Save$|^Create$/ }),
    );
    await waitFor(() => expectWordsNotJson("Role name cannot be empty"));
  });

  it("Clone says it in words", async () => {
    fireEvent.click(await screen.findByTitle("Clone"));
    const dialog = screen.getAllByRole("dialog").at(-1)!;
    fireEvent.change(within(dialog).getByRole("textbox"), {
      target: { value: "   " },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Clone" }));
    await waitFor(() => expectWordsNotJson("Clone name cannot be empty"));
  });
});
