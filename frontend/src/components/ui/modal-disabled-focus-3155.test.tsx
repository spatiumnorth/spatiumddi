/**
 * @vitest-environment jsdom
 *
 * A dialog keeps keyboard focus when its own focused button is disabled
 * while the request runs, so a refusal leaves focus inside the open dialog
 * (#3155, on top of #2723's removed-control case).
 */
import { useState } from "react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Modal } from "./modal";
import { DeleteConfirmModal } from "@/pages/dhcp/_shared";

// Chromium drops focus on <body> when the focused control becomes disabled,
// in the same task; jsdom keeps it on the disabled button. Model the browser
// with an observer registered BEFORE the dialog mounts, so it runs ahead of
// the trap's own observer, as the browser's fix-up does.
let fixup: MutationObserver | null = null;
beforeEach(() => {
  fixup = new MutationObserver(() => {
    const active = document.activeElement as HTMLElement | null;
    if (active && (active as HTMLButtonElement).disabled === true) {
      // jsdom's blur() is a no-op on a disabled element; focusing <body>
      // directly is the same end state the browser reaches.
      document.body.setAttribute("tabindex", "-1");
      document.body.focus();
      document.body.removeAttribute("tabindex");
    }
  });
  fixup.observe(document.body, {
    subtree: true,
    attributes: true,
    attributeFilter: ["disabled"],
  });
});
afterEach(() => {
  fixup?.disconnect();
  fixup = null;
  cleanup();
});

function Refusable() {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  return (
    <Modal title="Delete thing" onClose={() => {}}>
      {error && <p role="alert">{error}</p>}
      <button
        disabled={pending}
        onClick={() => {
          setPending(true);
          setTimeout(() => {
            setPending(false);
            setError("refused");
          }, 20);
        }}
      >
        Delete
      </button>
    </Modal>
  );
}

function RefusedDelete() {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <DeleteConfirmModal
      title="Delete Client Class"
      description="Delete class gold?"
      isPending={pending}
      error={error}
      onClose={() => {}}
      onConfirm={() => {
        setPending(true);
        setTimeout(() => {
          setPending(false);
          setError("Cannot delete client class gold: still referenced");
        }, 20);
      }}
    />
  );
}

async function settle() {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 30));
  });
}

describe("focus after a refused request (#3155)", () => {
  it("is inside the dialog once the focused button was disabled", async () => {
    const user = userEvent.setup();
    render(<Refusable />);
    const dialog = screen.getByRole("dialog", { name: "Delete thing" });
    const btn = screen.getByRole("button", { name: "Delete" });
    btn.focus();
    await user.keyboard("{Enter}");
    await screen.findByRole("alert");
    await settle();
    await waitFor(() => {
      expect(document.activeElement).not.toBe(document.body);
      expect(dialog.contains(document.activeElement)).toBe(true);
    });
  });

  it("keeps focus in the shared DHCP delete dialog and announces the refusal", async () => {
    const user = userEvent.setup();
    render(<RefusedDelete />);
    const dialog = screen.getByRole("dialog", { name: "Delete Client Class" });
    await user.click(screen.getByRole("checkbox"));
    const btn = screen.getByRole("button", { name: "Delete" });
    btn.focus();
    await user.keyboard("{Enter}");
    // The reason is a live alert, so a screen reader announces it.
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/still referenced/);
    await settle();
    expect(document.activeElement).not.toBe(document.body);
    expect(dialog.contains(document.activeElement)).toBe(true);
  });
});
