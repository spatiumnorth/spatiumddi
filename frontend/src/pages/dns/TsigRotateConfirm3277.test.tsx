/**
 * @vitest-environment jsdom
 *
 * #3277: a TSIG key's Rotate asks its second confirmation in rotate words.
 *
 * The per-key Rotate on a server group's TSIG Keys tab uses the two-step
 * ConfirmDestroyModal, whose step 2 defaults to the delete wording. It passed
 * none of the step-2 props, so step 2 read "Confirm Permanent Deletion",
 * "This action cannot be undone." and a Delete button that read "Deleting…"
 * while the request ran. The button rotates the key (POST
 * /dns/groups/{gid}/tsig-keys/{id}/rotate: a new secret replaces the stored
 * one and the key stays); nothing is deleted. The two steps and the checkbox
 * stay: a rotate breaks every client still using the old secret.
 *
 * The delete callers keep the defaults, so these tests also hold them.
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
import { ConfirmDestroyModal } from "./ConfirmDestroyModal";

/** Words that call the action a delete. */
const DELETE_WORDS = /delet|permanent|cannot be undone/i;

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

/** The key's Rotate, then Continue: the dialog's second step. */
async function toRotateStep2(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByText("k1");
  // The row's Rotate is gated on superadmin, which arrives asynchronously.
  const rotate = screen.getByRole("button", { name: "Rotate" });
  await waitFor(() =>
    expect((rotate as HTMLButtonElement).disabled).toBe(false),
  );
  await user.click(rotate);
  const step1 = screen.getByRole("dialog", { name: "Rotate TSIG Key" });
  await user.click(within(step1).getByRole("button", { name: "Continue" }));
  return screen.getByRole("dialog");
}

/** The step's confirming button: its last one that is not Cancel or Close. */
const confirmButton = (dialog: HTMLElement) =>
  within(dialog)
    .getAllByRole("button")
    .filter((b) => !/^(Cancel|Close)/.test(b.textContent ?? ""))
    .filter((b) => b.getAttribute("aria-label") !== "Close dialog")
    .at(-1) as HTMLButtonElement;

const words = (el: Element) => (el.textContent ?? "").replace(/\s+/g, " ");

describe("Rotate TSIG Key, step 2 (#3277)", () => {
  it("is titled, warned and buttoned as a rotate, not a permanent deletion", async () => {
    show();
    const user = userEvent.setup();
    const step2 = await toRotateStep2(user);
    const title = within(step2).getByRole("heading").textContent ?? "";
    const said = words(step2);
    const button = confirmButton(step2);

    expect(title, `step 2's title: "${title}"`).toMatch(/rotat/i);
    expect(title, `step 2's title: "${title}"`).not.toMatch(DELETE_WORDS);
    expect(said).not.toContain("This action cannot be undone.");
    expect(
      said.match(DELETE_WORDS)?.[0] ?? null,
      `step 2 calls the rotate a delete: "${said}"`,
    ).toBeNull();
    expect(button.textContent, "step 2's confirming button").toMatch(
      /^Rotate\b/,
    );
    expect(within(step2).queryByRole("button", { name: /delete/i })).toBeNull();
  });

  it("says it is rotating, not deleting, while the rotate runs", async () => {
    // The rotate stays in flight for the rest of the test.
    rotateTSIGKey.mockReturnValue(new Promise(() => {}));
    show();
    const user = userEvent.setup();
    const step2 = await toRotateStep2(user);
    await user.click(within(step2).getByRole("checkbox"));
    await user.click(confirmButton(step2));

    await waitFor(() =>
      expect(rotateTSIGKey).toHaveBeenCalledWith("g1", "k-1"),
    );
    const pending = confirmButton(screen.getByRole("dialog"));
    expect(pending.disabled).toBe(true);
    expect(pending.textContent).not.toMatch(/delet/i);
    expect(pending.textContent).toMatch(/^Rotating/);
  });

  it("still asks for the checkbox, then rotates the key and shows its new secret", async () => {
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
      secret: "bmV3LXNlY3JldA==",
    });
    show();
    const user = userEvent.setup();
    const step2 = await toRotateStep2(user);
    const button = confirmButton(step2);
    expect(button.textContent).toMatch(/^Rotate\b/);
    expect(button.disabled, "the confirm waits for the checkbox").toBe(true);
    await user.click(within(step2).getByRole("checkbox"));
    expect(button.disabled).toBe(false);
    await user.click(button);

    await waitFor(() =>
      expect(rotateTSIGKey).toHaveBeenCalledWith("g1", "k-1"),
    );
    const reveal = await screen.findByRole("dialog", {
      name: "Copy this secret now",
    });
    expect(words(reveal)).toContain("bmV3LXNlY3JldA==");
  });
});

describe("ConfirmDestroyModal step 2 (#3277)", () => {
  const base = {
    title: "Delete Server Group",
    description: "Removes it.",
    checkLabel: "I understand",
    onConfirm: () => {},
    onClose: () => {},
  };

  it("keeps the delete defaults when the caller passes no step-2 words", async () => {
    const user = userEvent.setup();
    const { rerender } = render(<ConfirmDestroyModal {...base} />);
    await user.click(screen.getByRole("button", { name: "Continue" }));
    const step2 = screen.getByRole("dialog", {
      name: "Confirm Permanent Deletion",
    });
    expect(words(step2)).toContain("This action cannot be undone.");
    expect(confirmButton(step2).textContent).toBe("Delete");

    rerender(<ConfirmDestroyModal {...base} isPending />);
    expect(confirmButton(screen.getByRole("dialog")).textContent).toBe(
      "Deleting…",
    );
  });

  it("shows the caller's pending label instead of Deleting…", async () => {
    const user = userEvent.setup();
    const words2 = {
      confirmTitle: "Confirm Rotation",
      warning: "The old secret stops working.",
      confirmButtonLabel: "Rotate key",
      pendingLabel: "Rotating…",
    };
    const { rerender } = render(<ConfirmDestroyModal {...base} {...words2} />);
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(confirmButton(screen.getByRole("dialog")).textContent).toBe(
      "Rotate key",
    );

    rerender(<ConfirmDestroyModal {...base} {...words2} isPending />);
    expect(confirmButton(screen.getByRole("dialog")).textContent).toBe(
      "Rotating…",
    );
  });
});
