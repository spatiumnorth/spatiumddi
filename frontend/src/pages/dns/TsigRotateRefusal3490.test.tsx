/**
 * @vitest-environment jsdom
 *
 * #3490: a refused TSIG key rotation says why, in the confirm dialog, as an
 * alert; success still closes and reveals the new secret.
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
    },
  };
});

import { TSIGKeysTab } from "./DNSPage";

afterEach(() => {
  cleanup();
  rotateTSIGKey.mockReset();
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
