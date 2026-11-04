/**
 * @vitest-environment jsdom
 *
 * #3441: Delete Option Template, Unblock MAC and Delete Phone Profile said
 * nothing when the server refused the delete. Each rendered
 * `DeleteConfirmModal` without its `error`, and each mutation had only an
 * `onSuccess`, so the dialog stayed open with its words unchanged. A row
 * deleted elsewhere answers 404 with its route's own detail, and a role
 * without delete answers 403. Each dialog now shows the server's reason, as
 * Delete Client Class does (#3113, #3124), and forgets it when it closes, so
 * the next row's dialog opens clean.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const del = vi.hoisted(() => ({
  template: vi.fn(),
  macBlock: vi.fn(),
  phoneProfile: vi.fn(),
}));

function template(id: string, name: string) {
  return {
    id,
    group_id: "g1",
    name,
    description: "",
    address_family: "ipv4",
    options: {},
  };
}

function macBlock(id: string, mac_address: string) {
  return {
    id,
    group_id: "g1",
    mac_address,
    reason: "rogue",
    description: "",
    enabled: true,
    expires_at: null,
    created_at: "2026-11-03T00:00:00Z",
    modified_at: "2026-11-03T00:00:00Z",
    created_by_user_id: null,
    updated_by_user_id: null,
    last_match_at: null,
    match_count: 0,
    vendor: null,
    ipam_matches: [],
  };
}

function phoneProfile(id: string, name: string) {
  return {
    id,
    group_id: "g1",
    name,
    description: "",
    enabled: true,
    vendor: null,
    vendor_class_match: null,
    option_set: [],
    tags: {},
    scope_ids: [],
    created_at: "2026-11-03T00:00:00Z",
    modified_at: "2026-11-03T00:00:00Z",
  };
}

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dhcpApi: {
      ...actual.dhcpApi,
      listOptionTemplates: () =>
        Promise.resolve([
          template("t1", "voip-options"),
          template("t2", "lab-options"),
        ]),
      deleteOptionTemplate: (...a: unknown[]) => del.template(...a),
      listMacBlocks: () =>
        Promise.resolve([
          macBlock("b1", "02:98:14:00:00:99"),
          macBlock("b2", "02:98:14:00:00:98"),
        ]),
      deleteMacBlock: (...a: unknown[]) => del.macBlock(...a),
      listPhoneProfiles: () =>
        Promise.resolve([
          phoneProfile("p1", "desk-phones"),
          phoneProfile("p2", "lobby-phones"),
        ]),
      deletePhoneProfile: (...a: unknown[]) => del.phoneProfile(...a),
    },
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
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

const { OptionTemplatesTab } = await import("./DHCPPage");
const { MacBlocksTab } = await import("./MacBlocksTab");
const { PhoneProfilesTab } = await import("./PhoneProfilesTab");

afterEach(() => {
  cleanup();
  del.template.mockReset();
  del.macBlock.mockReset();
  del.phoneProfile.mockReset();
});

type User = ReturnType<typeof userEvent.setup>;

// Each dialog leaves by a different way out (Cancel, the X, Escape); all
// three call the dialog's one onClose.
const DIALOGS = [
  {
    name: "Delete Option Template",
    Tab: OptionTemplatesTab,
    rows: ["voip-options", "lab-options"],
    deleteTitle: "Delete option template",
    mock: del.template,
    calledWith: ["g1", "t1"],
    notFound: "Template not found",
    forbidden: "Permission denied: need 'delete' on 'dhcp_option_template'",
    close: (user: User, dialog: HTMLElement) =>
      user.click(within(dialog).getByRole("button", { name: "Cancel" })),
  },
  {
    name: "Unblock MAC",
    Tab: MacBlocksTab,
    rows: ["02:98:14:00:00:99", "02:98:14:00:00:98"],
    deleteTitle: "Delete",
    mock: del.macBlock,
    calledWith: ["g1", "b1"],
    notFound: "MAC block not found",
    forbidden: "Permission denied: need 'delete' on 'dhcp_mac_block'",
    close: (user: User, dialog: HTMLElement) =>
      user.click(within(dialog).getByRole("button", { name: "Close dialog" })),
  },
  {
    name: "Delete Phone Profile",
    Tab: PhoneProfilesTab,
    rows: ["desk-phones", "lobby-phones"],
    deleteTitle: "Delete profile",
    mock: del.phoneProfile,
    calledWith: ["p1"],
    notFound: "Phone profile not found",
    forbidden: "Permission denied: need 'delete' on 'dhcp_scope'",
    close: (user: User) => user.keyboard("{Escape}"),
  },
];

type Dialog = (typeof DIALOGS)[number];

function refusal(status: number, detail: string) {
  return { isAxiosError: true, response: { status, data: { detail } } };
}

async function show(d: Dialog) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <d.Tab groupId="g1" />
    </QueryClientProvider>,
  );
  await screen.findByText(d.rows[0]);
  return userEvent.setup();
}

/** Open the delete on the n-th row and press Delete, the box ticked. */
async function confirmDelete(d: Dialog, user: User, n = 0) {
  await user.click(screen.getAllByTitle(d.deleteTitle)[n]);
  const dialog = await screen.findByRole("dialog", { name: d.name });
  await user.click(
    within(dialog).getByRole("checkbox", {
      name: "I understand this action cannot be undone.",
    }),
  );
  await user.click(within(dialog).getByRole("button", { name: "Delete" }));
  return dialog;
}

describe.each(DIALOGS)(
  "$name says why a refused delete failed (#3441)",
  (d) => {
    it.each([
      [404, d.notFound],
      [403, d.forbidden],
    ])("shows a %i refusal's reason and stays open", async (status, detail) => {
      d.mock.mockRejectedValue(refusal(status, detail));
      const user = await show(d);
      const dialog = await confirmDelete(d, user);
      const alert = await within(dialog).findByRole("alert");
      expect(alert.textContent).toBe(detail);
      expect(d.mock).toHaveBeenCalledWith(...d.calledWith);
      // Still open on the same row, with Delete pressable again.
      expect(
        within(dialog).getByText((t) => t.includes(d.rows[0])),
      ).toBeTruthy();
      const again = within(dialog).getByRole("button", { name: "Delete" });
      expect((again as HTMLButtonElement).disabled).toBe(false);
    });

    it("forgets the refusal when it closes, so the next row's opens clean", async () => {
      d.mock.mockRejectedValue(refusal(404, d.notFound));
      const user = await show(d);
      const dialog = await confirmDelete(d, user);
      await within(dialog).findByRole("alert");
      await d.close(user, dialog);
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

      await user.click(screen.getAllByTitle(d.deleteTitle)[1]);
      const next = await screen.findByRole("dialog", { name: d.name });
      expect(within(next).getByText((t) => t.includes(d.rows[1]))).toBeTruthy();
      expect(within(next).queryByRole("alert")).toBeNull();
      expect(screen.queryByText(d.notFound)).toBeNull();
    });

    it("closes when the delete goes through", async () => {
      d.mock.mockResolvedValue(undefined);
      const user = await show(d);
      await confirmDelete(d, user);
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      expect(d.mock).toHaveBeenCalledWith(...d.calledWith);
      expect(screen.queryByRole("alert")).toBeNull();
    });
  },
);
