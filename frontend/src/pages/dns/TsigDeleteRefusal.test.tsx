/**
 * @vitest-environment jsdom
 *
 * #2606 — Delete TSIG Key: the dialog says a cited key cannot be deleted
 * (the server refuses with 409, #2282) rather than that zones "will start
 * failing auth", and a refused delete shows the server's reason in the dialog.
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DNSServerGroup } from "@/lib/api";

const REASON =
  "Cannot delete TSIG key 'k1' — it is still referenced by zone 'z.test.' allow_transfer. BIND would refuse the whole server group's config with that key undefined. Remove the references first.";
const deleteTSIGKey = vi.fn();

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
      listTSIGKeys: () =>
        Promise.resolve([
          {
            id: "k-1",
            group_id: "g1",
            name: "k1",
            algorithm: "hmac-sha256",
            purpose: null,
            notes: "",
            last_rotated_at: null,
            created_at: "2026-10-01T00:00:00Z",
            modified_at: "2026-10-01T00:00:00Z",
            secret: null,
          },
        ]),
      deleteTSIGKey: (...a: unknown[]) => deleteTSIGKey(...a),
    },
  };
});

import { TSIGKeysTab } from "./DNSPage";

afterEach(() => {
  cleanup();
  deleteTSIGKey.mockReset();
});

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <TSIGKeysTab group={{ id: "g1" } as DNSServerGroup} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function toConfirmStep(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByText("k1");
  await user.click(screen.getByTitle("Delete key"));
  await user.click(screen.getByRole("button", { name: "Continue" }));
}

describe("Delete TSIG Key", () => {
  it("says a cited key cannot be deleted, not that zones start failing auth", async () => {
    show();
    const user = userEvent.setup();
    await screen.findByText("k1");
    await user.click(screen.getByTitle("Delete key"));
    const said = document.body.textContent ?? "";
    expect(said).not.toMatch(/start failing auth/);
    expect(said).toMatch(/still cites cannot be deleted/);
    expect(said).toMatch(/server refuses, names what cites it/);
  });

  it("shows the server's 409 reason and keeps the dialog open", async () => {
    deleteTSIGKey.mockRejectedValue({
      response: {
        status: 409,
        data: { detail: { field: "name", message: REASON, references: [] } },
      },
    });
    show();
    const user = userEvent.setup();
    await toConfirmStep(user);
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(document.body.textContent).toContain(
        "still referenced by zone 'z.test.' allow_transfer",
      ),
    );
    expect(screen.getByRole("button", { name: "Delete" })).toBeTruthy();
  });

  it("closes the dialog when the delete succeeds", async () => {
    deleteTSIGKey.mockResolvedValue(undefined);
    show();
    const user = userEvent.setup();
    await toConfirmStep(user);
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(screen.queryByRole("checkbox")).toBeNull());
  });
});
