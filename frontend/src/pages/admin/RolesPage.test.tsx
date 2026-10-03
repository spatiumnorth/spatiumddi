/**
 * @vitest-environment jsdom
 *
 * A role's dialog shows the grants the role holds (#1394).
 *
 * Built-in roles cannot be edited, so Roles → View is the only place the
 * console shows what one grants. The dialog renders each grant as two
 * selects whose options are fixed lists; a stored action or resource type
 * outside those lists (`approve`, `appliance`, `change_request`, …) fell
 * back to the list's first option, so Appliance Operator's one grant,
 * admin on appliance, read "admin · *", and Change Approver showed no
 * approve at all. Nine of the twelve built-in roles hold such grants. A
 * custom role's Edit dialog showed the same wrong values.
 *
 * The contract: every grant row shows the action and the resource type the
 * role stores, built-in or custom, and an untouched row is saved as stored.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
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
/** Per API object, the calls a test answers. Anything else stays pending. */
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

const { RolesPage } = await import("@/pages/admin/RolesPage");

type Grant = { action: string; resource_type: string; resource_id?: string };

/** Built-in roles as the server seeds them (backend/app/main.py). */
const APPLIANCE_OPERATOR = {
  id: "role-ao",
  name: "Appliance Operator",
  description: "",
  is_builtin: true,
  permissions: [{ action: "admin", resource_type: "appliance" }],
};
const CHANGE_APPROVER = {
  id: "role-ca",
  name: "Change Approver",
  description: "",
  is_builtin: true,
  permissions: [
    { action: "approve", resource_type: "change_request" },
    { action: "read", resource_type: "change_request" },
  ],
};
const VIEWER = {
  id: "role-v",
  name: "Viewer",
  description: "",
  is_builtin: true,
  permissions: [{ action: "read", resource_type: "*" }],
};
/** A custom role holding a type the dialog's list does not name. */
const CUSTOM = {
  id: "role-c",
  name: "NAT desk",
  description: "",
  is_builtin: false,
  permissions: [
    { action: "admin", resource_type: "nat_mapping" },
    { action: "read", resource_type: "subnet" },
  ],
};

function show(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/admin/roles"]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

/** What the dialog shows for each grant row: its two selects' chosen options. */
function shownGrants(dialog: HTMLElement): string[] {
  const out: string[] = [];
  for (const row of Array.from(dialog.querySelectorAll("div"))) {
    const selects = Array.from(row.children).filter(
      (c): c is HTMLSelectElement => c.tagName === "SELECT",
    );
    if (selects.length >= 2) {
      out.push(
        selects
          .slice(0, 2)
          .map((s) => s.selectedOptions[0]?.textContent ?? "")
          .join(" "),
      );
    }
  }
  return out;
}

async function openDialog(role: { name: string; is_builtin: boolean }) {
  const cell = await screen.findByRole("cell", { name: role.name });
  const row = cell.closest("tr") as HTMLElement;
  fireEvent.click(
    within(row).getByTitle(role.is_builtin ? "View" : "Edit", { exact: true }),
  );
  const dialogs = screen.getAllByRole("dialog");
  return dialogs[dialogs.length - 1];
}

afterEach(() => {
  cleanup();
  for (const k of Object.keys(answers)) delete answers[k];
});

describe("Roles: a role's dialog shows the grants it holds", () => {
  it.each([APPLIANCE_OPERATOR, CHANGE_APPROVER, VIEWER, CUSTOM])(
    "$name",
    async (role) => {
      answers.rolesApi = {
        list: async () => [APPLIANCE_OPERATOR, CHANGE_APPROVER, VIEWER, CUSTOM],
      };
      show(<RolesPage />);

      const dialog = await openDialog(role);

      expect(
        shownGrants(dialog),
        `the dialog for ${role.name} shows other grants than the role holds`,
      ).toEqual(
        role.permissions.map((g: Grant) => `${g.action} ${g.resource_type}`),
      );
    },
  );

  it("saves a custom role's untouched grants as stored", async () => {
    const update = vi.fn(async () => ({}));
    answers.rolesApi = { list: async () => [CUSTOM], update };
    show(<RolesPage />);

    const dialog = await openDialog(CUSTOM);
    fireEvent.click(within(dialog).getByRole("button", { name: /^Save$/ }));

    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith(
      CUSTOM.id,
      expect.objectContaining({ permissions: CUSTOM.permissions }),
    );
  });
});
