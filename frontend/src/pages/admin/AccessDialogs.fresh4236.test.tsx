/**
 * @vitest-environment jsdom
 *
 * Edit user, Edit role and Edit group re-read the row when they open and send
 * only the fields the operator changed (#3863, #4236). The list the page holds
 * can predate a change another writer made; the dialog used to seed from it
 * and send every access field back, undoing that change on any Save.
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
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { UsersPage } = await import("@/pages/admin/UsersPage");
const { RolesPage } = await import("@/pages/admin/RolesPage");
const { GroupsPage } = await import("@/pages/admin/GroupsPage");

function show(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  answers.authApi = {
    myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    listProviders: async () => [],
  };
  answers.authProvidersApi = { list: async () => [] };
});

afterEach(() => {
  cleanup();
  for (const k of Object.keys(answers)) delete answers[k];
});

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

describe("Edit user", () => {
  async function open() {
    let server = { ...USER };
    const update = vi.fn(async () => ({}));
    answers.usersApi = { list: async () => [{ ...server }], update };
    show(<UsersPage />);
    await screen.findByTitle("Edit");
    // Another writer disables the user after the list loaded.
    server = { ...USER, is_active: false };
    fireEvent.click(screen.getByTitle("Edit"));
    const dialog = await screen.findByRole("dialog");
    return { dialog, update };
  }

  it("a display-name Save does not re-enable a user disabled since the list loaded", async () => {
    const { dialog, update } = await open();
    const name = within(dialog).getByDisplayValue("Someone");
    fireEvent.change(name, { target: { value: "Someone Else" } });
    fireEvent.click(within(dialog).getByRole("button", { name: /^Save$/ }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith(USER.id, {
      display_name: "Someone Else",
    });
  });

  it("shows the fresh state, and a real change to Active is still sent", async () => {
    const { dialog, update } = await open();
    const active = within(dialog).getByLabelText("Active") as HTMLInputElement;
    expect(active.checked).toBe(false);
    fireEvent.click(active);
    fireEvent.click(within(dialog).getByRole("button", { name: /^Save$/ }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith(USER.id, { is_active: true });
  });
});

const ROLE = {
  id: "role-c",
  name: "Desk",
  description: "old",
  is_builtin: false,
  permissions: [
    { action: "read", resource_type: "user" },
    { action: "read", resource_type: "group" },
  ],
};

describe("Edit role", () => {
  async function open() {
    let server = { ...ROLE };
    const update = vi.fn(async () => ({}));
    answers.rolesApi = { list: async () => [{ ...server }], update };
    show(<RolesPage />);
    await screen.findByRole("cell", { name: ROLE.name });
    // Another writer revokes a grant after the list loaded.
    server = { ...ROLE, permissions: [ROLE.permissions[0]] };
    fireEvent.click(screen.getByTitle("Edit", { exact: true }));
    const dialog = await screen.findByRole("dialog");
    return { dialog, update };
  }

  it("a description Save does not send the permissions back", async () => {
    const { dialog, update } = await open();
    fireEvent.change(within(dialog).getByDisplayValue("old"), {
      target: { value: "new" },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: /^Save$/ }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith(ROLE.id, { description: "new" });
  });

  it("a real change to the grants is still sent, from the fresh list", async () => {
    const { dialog, update } = await open();
    fireEvent.click(within(dialog).getByTitle("Remove row"));
    fireEvent.click(within(dialog).getByRole("button", { name: /^Save$/ }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith(ROLE.id, { permissions: [] });
  });
});

const GROUP = {
  id: "g-1",
  name: "Team",
  description: "old",
  auth_source: "local",
  role_ids: ["r-1"],
  user_ids: ["u-1", "u-2"],
};

describe("Edit group", () => {
  async function open() {
    let server = { ...GROUP };
    const update = vi.fn(async () => ({}));
    answers.groupsApi = { list: async () => [{ ...server }], update };
    answers.rolesApi = {
      list: async () => [
        { id: "r-1", name: "Role One", description: "", is_builtin: false },
      ],
    };
    answers.usersApi = {
      list: async () => [
        { ...USER, id: "u-1", username: "alice" },
        { ...USER, id: "u-2", username: "bob" },
      ],
    };
    show(<GroupsPage />);
    await screen.findByTitle("Edit");
    // Another writer removes a member after the list loaded.
    server = { ...GROUP, user_ids: ["u-1"] };
    fireEvent.click(screen.getByTitle("Edit"));
    const dialog = await screen.findByRole("dialog");
    return { dialog, update };
  }

  it("a description Save does not send role_ids or user_ids back", async () => {
    const { dialog, update } = await open();
    fireEvent.change(within(dialog).getByDisplayValue("old"), {
      target: { value: "new" },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: /^Save$/ }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith(GROUP.id, { description: "new" });
  });

  it("a real membership change is still sent, from the fresh list", async () => {
    const { dialog, update } = await open();
    fireEvent.click(within(dialog).getByLabelText(/bob/));
    fireEvent.click(within(dialog).getByRole("button", { name: /^Save$/ }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith(GROUP.id, {
      user_ids: ["u-1", "u-2"],
    });
  });
});
