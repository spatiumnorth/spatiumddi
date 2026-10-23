/**
 * @vitest-environment jsdom
 *
 * #2444 — deleting a DNS ACL another ACL cites is refused (409); the reason
 * is shown and the dialog stays open, instead of closing in silence.
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const REASON =
  "Cannot delete ACL 'a' - it is still referenced by ACL 'b'. Remove the references first.";
const deleteAcl = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    },
    dnsApi: {
      ...actual.dnsApi,
      listAcls: () =>
        Promise.resolve([
          { id: "1", name: "a", description: "", entries: [] },
          { id: "2", name: "b", description: "", entries: [] },
        ]),
      deleteAcl: (...a: unknown[]) => deleteAcl(...a),
    },
  };
});

import { AclsTab } from "./DNSPage";

afterEach(() => {
  cleanup();
  deleteAcl.mockReset();
});

// The dialog's confirm button carries the text; the row's trash icon only a title.
const confirmBtns = () =>
  screen
    .queryAllByRole("button", { name: "Delete ACL" })
    .filter((b) => b.textContent === "Delete ACL");

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AclsTab groupId="g1" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ACL delete refusal", () => {
  it("shows the server's reason and keeps the dialog open", async () => {
    deleteAcl.mockRejectedValue({
      response: { status: 409, data: { detail: REASON } },
    });
    show();
    await screen.findByText("a");
    const user = userEvent.setup();
    await user.click(screen.getAllByTitle("Delete ACL")[0]);
    await user.click(confirmBtns()[0]);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("still referenced by ACL 'b'");
    expect(confirmBtns()).toHaveLength(1);
  });

  it("closes the dialog when the delete succeeds", async () => {
    deleteAcl.mockResolvedValue(undefined);
    show();
    await screen.findByText("a");
    const user = userEvent.setup();
    await user.click(screen.getAllByTitle("Delete ACL")[0]);
    await user.click(confirmBtns()[0]);
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
    await waitFor(() => expect(confirmBtns()).toHaveLength(0));
  });
});
