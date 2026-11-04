/**
 * @vitest-environment jsdom
 *
 * #3396: a refused Delete PXE profile says why. Since #3387 the server
 * refuses (409) to delete a profile while a pool's class restriction names
 * the class one of its boot rules generates; a profile deleted elsewhere
 * answers 404, and a role without delete 403. The dialog stayed open with
 * its words unchanged, and nothing said why.
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
import { MemoryRouter, Route, Routes } from "react-router-dom";

const POOL_DETAIL =
  "Cannot delete PXE profile 'ubuntu': boot rule 'ipxe.efi' generates class " +
  "'pxe-0a1b2c3d-4e5f6a7b', which is still referenced by 1 pool(s) " +
  "(10.0.0.100-10.0.0.150). Kea accepts a reference to an undefined class " +
  "and the pool would silently match no client. Clear or change those " +
  "references first.";

const deletePxeProfile = vi.fn();

function profile(id: string, name: string) {
  return {
    id,
    group_id: "g1",
    name,
    description: "",
    next_server: "10.0.0.5",
    enabled: true,
    tags: {},
    matches: [],
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
      getGroup: () => Promise.resolve({ id: "g1", name: "grp" }),
      listPxeProfiles: () =>
        Promise.resolve([profile("p1", "ubuntu"), profile("p2", "debian")]),
      deletePxeProfile: (...a: unknown[]) => deletePxeProfile(...a),
    },
  };
});
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return { ...actual, usePermissions: () => ({ can: () => true }) };
});

const { PXEProfilesPage } = await import("./PXEProfilesPage");

afterEach(() => {
  cleanup();
  deletePxeProfile.mockReset();
});

function refusal(status: number, detail: string) {
  return { isAxiosError: true, response: { status, data: { detail } } };
}

async function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/dhcp/groups/g1/pxe"]}>
        <Routes>
          <Route
            path="/dhcp/groups/:groupId/pxe"
            element={<PXEProfilesPage />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByText("ubuntu");
  return userEvent.setup();
}

/** Open Delete on the n-th profile card and press the dialog's Delete. */
async function confirmDelete(user: ReturnType<typeof userEvent.setup>, n = 0) {
  await user.click(screen.getAllByTitle("Delete")[n]);
  const dialog = await screen.findByRole("dialog", {
    name: "Delete PXE profile",
  });
  await user.click(within(dialog).getByRole("button", { name: "Delete" }));
  return dialog;
}

describe("Delete PXE profile refusals (#3396)", () => {
  it("shows the server's 409 reason and keeps the dialog open", async () => {
    deletePxeProfile.mockRejectedValue(refusal(409, POOL_DETAIL));
    const user = await show();
    const dialog = await confirmDelete(user);
    const alert = await within(dialog).findByRole("alert");
    expect(alert.textContent).toBe(POOL_DETAIL);
    expect(deletePxeProfile).toHaveBeenCalledWith("p1");
    // Still open on the same profile, with Delete pressable again.
    expect(within(dialog).getByText("ubuntu")).toBeTruthy();
    const again = within(dialog).getByRole("button", { name: "Delete" });
    expect((again as HTMLButtonElement).disabled).toBe(false);
  });

  it.each([
    [403, "Permission denied: need 'delete' on 'dhcp_scope'"],
    [404, "PXE profile not found"],
  ])("shows the reason of a %i refusal too", async (status, detail) => {
    deletePxeProfile.mockRejectedValue(refusal(status, detail));
    const user = await show();
    const dialog = await confirmDelete(user);
    expect((await within(dialog).findByRole("alert")).textContent).toBe(detail);
  });

  it("forgets the refusal when the dialog closes", async () => {
    deletePxeProfile.mockRejectedValue(refusal(409, POOL_DETAIL));
    const user = await show();
    const dialog = await confirmDelete(user);
    await within(dialog).findByRole("alert");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    // Reopened on the other profile, the first one's refusal is not shown.
    await user.click(screen.getAllByTitle("Delete")[1]);
    const again = await screen.findByRole("dialog", {
      name: "Delete PXE profile",
    });
    expect(within(again).getByText("debian")).toBeTruthy();
    expect(within(again).queryByRole("alert")).toBeNull();
    expect(screen.queryByText(POOL_DETAIL)).toBeNull();
  });

  it("closes the dialog when the delete succeeds", async () => {
    deletePxeProfile.mockResolvedValue({ status: 204 });
    const user = await show();
    await confirmDelete(user);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
