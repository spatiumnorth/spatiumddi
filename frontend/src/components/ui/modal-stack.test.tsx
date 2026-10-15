/**
 * @vitest-environment jsdom
 *
 * Dialog stacking: Esc and Tab belong to the topmost dialog (#1947, #1948).
 */
import { afterEach, describe, expect, it } from "vitest";
import { useState } from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Modal } from "./modal";
import { ConfirmModal } from "./confirm-modal";

function Stack() {
  const [outer, setOuter] = useState(true);
  const [inner, setInner] = useState(false);
  return (
    <div>
      <button>page-behind</button>
      {outer && (
        <Modal title="Outer" onClose={() => setOuter(false)}>
          <input aria-label="outer-first" />
          <button onClick={() => setInner(true)}>open-inner</button>
          {inner && (
            <Modal title="Inner" onClose={() => setInner(false)}>
              <input aria-label="inner-first" />
              <input aria-label="inner-last" />
            </Modal>
          )}
        </Modal>
      )}
    </div>
  );
}

afterEach(cleanup);

describe("dialog stack", () => {
  it("is a modal dialog labelled by its title", () => {
    render(<Stack />);
    const dlg = screen.getByRole("dialog", { name: "Outer" });
    expect(dlg.getAttribute("aria-modal")).toBe("true");
    expect(dlg.getAttribute("aria-labelledby")).toBeTruthy();
  });

  it("Esc closes only the topmost dialog, one per press", async () => {
    const user = userEvent.setup();
    render(<Stack />);
    await user.click(screen.getByText("open-inner"));
    expect(screen.getAllByRole("dialog")).toHaveLength(2);
    await user.keyboard("{Escape}");
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    expect(screen.getByRole("dialog", { name: "Outer" })).toBeTruthy();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("Esc closes only a ConfirmModal opened over another dialog", async () => {
    function C() {
      const [o, setO] = useState(true);
      const [c, setC] = useState(true);
      return (
        <>
          {o && (
            <Modal title="Edit" onClose={() => setO(false)}>
              <input aria-label="f" />
              <ConfirmModal
                open={c}
                title="Sure?"
                message="x"
                confirmLabel="Yes"
                onConfirm={() => {}}
                onClose={() => setC(false)}
              />
            </Modal>
          )}
        </>
      );
    }
    const user = userEvent.setup();
    render(<C />);
    expect(screen.getAllByRole("dialog")).toHaveLength(2);
    await user.keyboard("{Escape}");
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    expect(screen.getByRole("dialog", { name: "Edit" })).toBeTruthy();
  });

  it("Shift+Tab from the first control wraps to the last; Tab wraps back", async () => {
    const user = userEvent.setup();
    render(<Stack />);
    await user.click(screen.getByText("open-inner"));
    // Initial focus is the first control, not the close button.
    expect(document.activeElement).toBe(screen.getByLabelText("inner-first"));
    // The close button is first in tab order; one more Shift+Tab wraps.
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(
      within(screen.getByRole("dialog", { name: "Inner" })).getByRole(
        "button",
        { name: "Close dialog" },
      ),
    );
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(screen.getByLabelText("inner-last"));
    await user.tab();
    expect(document.activeElement).toBe(
      within(screen.getByRole("dialog", { name: "Inner" })).getByRole(
        "button",
        { name: "Close dialog" },
      ),
    );
  });

  it("Shift+Tab from the dialog container stays in the dialog", async () => {
    const user = userEvent.setup();
    render(
      <>
        <button>page-behind</button>
        <Modal title="Bare" onClose={() => {}}>
          <p>no controls here</p>
        </Modal>
      </>,
    );
    const dlg = screen.getByRole("dialog");
    expect(dlg.contains(document.activeElement)).toBe(true);
    await user.tab({ shift: true });
    expect(dlg.contains(document.activeElement)).toBe(true);
    await user.tab({ shift: true });
    expect(dlg.contains(document.activeElement)).toBe(true);
  });

  it("only the topmost dialog traps Tab", async () => {
    const user = userEvent.setup();
    render(<Stack />);
    await user.click(screen.getByText("open-inner"));
    const inner = screen.getByRole("dialog", { name: "Inner" });
    for (let i = 0; i < 6; i++) {
      await user.tab();
      expect(inner.contains(document.activeElement)).toBe(true);
    }
  });

  it("returns focus to the opener on close", async () => {
    const user = userEvent.setup();
    render(<Stack />);
    const opener = screen.getByText("open-inner");
    await user.click(opener);
    await user.keyboard("{Escape}");
    expect(document.activeElement).toBe(opener);
  });
});
