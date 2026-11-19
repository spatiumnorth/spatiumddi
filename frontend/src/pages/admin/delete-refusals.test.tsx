/**
 * @vitest-environment jsdom
 *
 * Delete User and Delete Group say why a delete was refused (#2436).
 * A 404 means the object is already gone: the dialog closes. Any other
 * refusal (400 own account, 409 last superadmin) is said in the dialog.
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

const USER = {
  id: "u-1",
  username: "victim",
  email: "v@example.com",
  display_name: "Victim",
  is_active: true,
  is_superadmin: false,
  force_password_change: false,
  auth_source: "local",
  last_login_at: null,
};
const GROUP = {
  id: "g-1",
  name: "doomed",
  description: "",
  auth_source: "internal",
  role_ids: [],
  user_ids: [],
};

function answered(status: number, detail: string) {
  return Object.assign(new Error(`Request failed with status code ${status}`), {
    isAxiosError: true,
    response: { status, data: { detail } },
  });
}

let deleteError: unknown;

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    usersApi: {
      list: () => Promise.resolve([USER]),
      delete: () => Promise.reject(deleteError),
    },
    groupsApi: {
      list: () => Promise.resolve([GROUP]),
      delete: () => Promise.reject(deleteError),
    },
    rolesApi: { list: () => Promise.resolve([]) },
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
const { GroupsPage } = await import("@/pages/admin/GroupsPage");

function open(page: React.ReactElement) {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>{page}</MemoryRouter>
    </QueryClientProvider>,
  );
}

async function pressDelete(modalTitle: string) {
  fireEvent.click(await screen.findByTitle("Delete"));
  await screen.findByText(modalTitle);
  // The row's own Delete icon button shares the name; the dialog's is last.
  fireEvent.click(screen.getAllByRole("button", { name: "Delete" }).at(-1)!);
}

beforeEach(() => {
  deleteError = undefined;
});
afterEach(cleanup);

const CASES = [
  ["Delete User", "User", <UsersPage key="u" />],
  ["Delete Group", "Group", <GroupsPage key="g" />],
] as const;

describe.each(CASES)("%s", (title, noun, page) => {
  it("closes when the object is already gone (404)", async () => {
    deleteError = answered(404, `${noun} not found`);
    open(page);
    await pressDelete(title);
    await waitFor(() => expect(screen.queryByText(title)).toBeNull());
  });

  it("says why a refused delete was refused", async () => {
    deleteError = answered(409, "Would leave no active superadmin");
    open(page);
    await pressDelete(title);
    await screen.findByText("Would leave no active superadmin");
    expect(screen.queryByText(title)).not.toBeNull();
  });
});
