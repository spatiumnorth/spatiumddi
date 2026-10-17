/**
 * @vitest-environment jsdom
 *
 * Focus return (#2050): a dialog whose field is `autoFocus`ed must still hand
 * focus back to its opener on close. The opener has to be read before React's
 * commit-time autofocus moves focus into the dialog.
 */
import { useState } from "react";
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Modal } from "./modal";

function Host({
  autoFocus,
  removeOpener,
}: {
  autoFocus: boolean;
  removeOpener?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [showOpener, setShowOpener] = useState(true);
  return (
    <div>
      {showOpener && <button onClick={() => setOpen(true)}>Open it</button>}
      {open && (
        <Modal
          title="Thing"
          onClose={() => {
            setOpen(false);
            if (removeOpener) setShowOpener(false);
          }}
        >
          <input aria-label="name" autoFocus={autoFocus} />
        </Modal>
      )}
    </div>
  );
}

afterEach(cleanup);

describe.each([true, false])("focus return (autoFocus=%s)", (autoFocus) => {
  it("returns to the opener on Esc", async () => {
    const user = userEvent.setup();
    render(<Host autoFocus={autoFocus} />);
    const opener = screen.getByRole("button", { name: "Open it" });
    await user.click(opener);
    expect(screen.getByRole("dialog")).toBeTruthy();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it("returns to the opener on the close button", async () => {
    const user = userEvent.setup();
    render(<Host autoFocus={autoFocus} />);
    const opener = screen.getByRole("button", { name: "Open it" });
    await user.click(opener);
    await user.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(document.activeElement).toBe(opener);
  });
});

it("does not throw when the opener was removed from the DOM", async () => {
  const user = userEvent.setup();
  render(<Host autoFocus removeOpener />);
  await user.click(screen.getByRole("button", { name: "Open it" }));
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.queryByRole("button", { name: "Open it" })).toBeNull();
});
