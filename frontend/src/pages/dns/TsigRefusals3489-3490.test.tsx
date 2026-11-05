/**
 * @vitest-environment jsdom
 *
 * #3490: a refused TSIG key rotation says why, in the confirm dialog, as an
 * alert; success still closes and reveals the new secret.
 *
 * #3489: a refused TSIG key delete already showed its reason in the same
 * shared confirm, in a box nothing announced; it is an alert now, and a
 * repeat refusal with the same words is a fresh alert, not the old node.
 */
import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DNSServerGroup } from "@/lib/api";

const rotateTSIGKey = vi.fn();
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
      rotateTSIGKey: (...a: unknown[]) => rotateTSIGKey(...a),
      deleteTSIGKey: (...a: unknown[]) => deleteTSIGKey(...a),
    },
  };
});

import { TSIGKeysTab } from "./DNSPage";

afterEach(() => {
  cleanup();
  rotateTSIGKey.mockReset();
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

async function submitRotate(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByText("k1");
  const rotate = screen.getByRole("button", { name: "Rotate" });
  await waitFor(() =>
    expect((rotate as HTMLButtonElement).disabled).toBe(false),
  );
  await user.click(rotate);
  await user.click(screen.getByRole("button", { name: "Continue" }));
  await user.click(screen.getByRole("checkbox"));
  await user.click(screen.getByRole("button", { name: "Rotate key" }));
}

describe("a refused TSIG rotate (#3490)", () => {
  it.each([
    [403, "Superadmin required"],
    [404, "TSIG key not found"],
    [409, "The key is locked by another change"],
    [422, "Nope, not valid"],
  ])(
    "shows the %i reason as an alert and keeps the dialog",
    async (status, detail) => {
      rotateTSIGKey.mockRejectedValue({
        response: { status, data: { detail } },
      });
      show();
      const user = userEvent.setup();
      await submitRotate(user);
      const alert = await screen.findByRole("alert");
      expect(alert.textContent).toContain(detail);
      const dialog = screen.getByRole("dialog", {
        name: "Confirm TSIG Key Rotation",
      });
      expect(
        within(dialog).getByRole("button", { name: "Rotate key" }),
      ).toBeTruthy();
      expect(
        screen.queryByRole("dialog", { name: "Copy this secret now" }),
      ).toBeNull();
    },
  );

  it("says a validation-array refusal through the shared formatter", async () => {
    rotateTSIGKey.mockRejectedValue({
      response: {
        status: 422,
        data: {
          detail: [
            { loc: ["body", "algorithm"], msg: "Value error, bad algorithm" },
          ],
        },
      },
    });
    show();
    const user = userEvent.setup();
    await submitRotate(user);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("algorithm: bad algorithm");
  });

  it("announces a repeat refusal with the same words afresh", async () => {
    rotateTSIGKey.mockRejectedValue({
      response: { status: 404, data: { detail: "TSIG key not found" } },
    });
    show();
    const user = userEvent.setup();
    await submitRotate(user);
    const first = await screen.findByRole("alert");
    await user.click(screen.getByRole("button", { name: "Rotate key" }));
    await waitFor(() => expect(rotateTSIGKey).toHaveBeenCalledTimes(2));
    const second = await screen.findByRole("alert");
    await waitFor(() => expect(first.isConnected).toBe(false));
    expect(second).not.toBe(first);
    expect(second.textContent).toBe("TSIG key not found");
  });

  it("clears the reason when the dialog is closed and reopened", async () => {
    rotateTSIGKey.mockRejectedValue({
      response: { status: 403, data: { detail: "Denied" } },
    });
    show();
    const user = userEvent.setup();
    await submitRotate(user);
    await screen.findByRole("alert");
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.click(screen.getByRole("button", { name: "Rotate" }));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("closes and reveals the secret on success", async () => {
    rotateTSIGKey.mockResolvedValue({
      id: "k-1",
      group_id: "g1",
      name: "k1",
      algorithm: "hmac-sha256",
      purpose: null,
      notes: "",
      last_rotated_at: "2026-11-01T18:00:00Z",
      created_at: "2026-10-01T00:00:00Z",
      modified_at: "2026-11-01T18:00:00Z",
      secret: "bmV3",
    });
    show();
    const user = userEvent.setup();
    await submitRotate(user);
    await screen.findByRole("dialog", { name: "Copy this secret now" });
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

async function submitDelete(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByText("k1");
  const del = screen.getByRole("button", { name: "Delete key" });
  await waitFor(() => expect((del as HTMLButtonElement).disabled).toBe(false));
  await user.click(del);
  await user.click(screen.getByRole("button", { name: "Continue" }));
  await user.click(screen.getByRole("checkbox"));
  await user.click(screen.getByRole("button", { name: "Delete" }));
}

describe("a refused TSIG delete is announced (#3489)", () => {
  const reason =
    "name: Cannot delete TSIG key 'k1' — it is still referenced by view 'v1' match_clients.";

  it("puts the server's reason in an alert and keeps the dialog", async () => {
    deleteTSIGKey.mockRejectedValue({
      response: { status: 409, data: { detail: reason } },
    });
    show();
    const user = userEvent.setup();
    await submitDelete(user);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe(reason);
    const dialog = screen.getByRole("dialog", {
      name: "Confirm Permanent Deletion",
    });
    expect(within(dialog).getByRole("alert")).toBe(alert);
  });

  it("announces a repeat refusal with the same words afresh", async () => {
    deleteTSIGKey.mockRejectedValue({
      response: { status: 409, data: { detail: reason } },
    });
    show();
    const user = userEvent.setup();
    await submitDelete(user);
    const first = await screen.findByRole("alert");
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(deleteTSIGKey).toHaveBeenCalledTimes(2));
    const second = await screen.findByRole("alert");
    await waitFor(() => expect(first.isConnected).toBe(false));
    expect(second).not.toBe(first);
    expect(second.textContent).toBe(reason);
  });

  it("opens without a stale alert after a refusal", async () => {
    deleteTSIGKey.mockRejectedValue({
      response: { status: 409, data: { detail: reason } },
    });
    show();
    const user = userEvent.setup();
    await submitDelete(user);
    await screen.findByRole("alert");
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.click(screen.getByRole("button", { name: "Delete key" }));
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
