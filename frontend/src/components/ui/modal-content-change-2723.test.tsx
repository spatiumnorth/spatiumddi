/**
 * @vitest-environment jsdom
 *
 * A dialog whose content changes while it is open keeps the operator's
 * keyboard place (#2723): a two-step delete's second step takes focus, and a
 * dialog that replaces a loading dialog returns focus to the original opener.
 */
import { useState } from "react";
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Modal } from "./modal";
import { ConfirmDestroyModal } from "@/pages/dns/ConfirmDestroyModal";

afterEach(cleanup);

describe("two-step delete (#2723a)", () => {
  it("moves focus into step 2 when Continue is pressed", async () => {
    const user = userEvent.setup();
    render(
      <ConfirmDestroyModal
        title="Delete Server Group"
        description="Removes it."
        checkLabel="I understand"
        onConfirm={() => {}}
        onClose={() => {}}
      />,
    );
    const cont = screen.getByRole("button", { name: "Continue" });
    cont.focus();
    await user.keyboard("{Enter}");
    const dialog = await screen.findByRole("dialog", {
      name: "Confirm Permanent Deletion",
    });
    await waitFor(() =>
      expect(dialog.contains(document.activeElement)).toBe(true),
    );
    expect(document.activeElement).not.toBe(document.body);
  });
});

function LoadingThenConfirm() {
  const [ready, setReady] = useState(false);
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button onClick={() => setOpen(true)}>Delete Group</button>
      {open && !ready && (
        <Modal title="Loading" onClose={() => setOpen(false)}>
          <p>Checking…</p>
          <button onClick={() => setReady(true)}>finish loading</button>
        </Modal>
      )}
      {open && ready && (
        <ConfirmDestroyModal
          title="Delete Server Group"
          description="Removes it."
          checkLabel="I understand"
          onConfirm={() => {}}
          onClose={() => setOpen(false)}
        />
      )}
    </div>
  );
}

describe("loading dialog handing over to its confirm (#2723b)", () => {
  it("returns focus to the button that opened the first one", async () => {
    const user = userEvent.setup();
    render(<LoadingThenConfirm />);
    const opener = screen.getByRole("button", { name: "Delete Group" });
    await user.click(opener);
    const loading = await screen.findByRole("dialog", { name: "Loading" });
    // Focus sits on the loading dialog's own card when it is replaced.
    loading.focus();
    // Finish loading without the card losing focus.
    const finish = screen.getByRole("button", { name: "finish loading" });
    finish.click();
    await screen.findByRole("dialog", { name: "Delete Server Group" });
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
  });
});
