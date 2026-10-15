/**
 * @vitest-environment jsdom
 *
 * Dialog stacking: Esc and Tab belong to the topmost dialog (#1947, #1948).
 *
 * jsdom does no layout, so `offsetParent` is always null there. The focus
 * trap on main filtered its tabbable controls on `offsetParent`, which made
 * it see NO controls under jsdom and swallow every Tab — so a trap test
 * passed there whatever the trap did. `offsetParent` is stubbed to the
 * parent node, as a browser reports it for a rendered element, so the tests
 * exercise the trap's real wrap logic.
 */
import { StrictMode, useState } from "react";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Modal } from "./modal";
import { ConfirmModal } from "./confirm-modal";

const realOffsetParent = Object.getOwnPropertyDescriptor(
  HTMLElement.prototype,
  "offsetParent",
);
beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, "offsetParent", {
    configurable: true,
    get(this: HTMLElement) {
      return this.isConnected ? this.parentNode : null;
    },
  });
});
afterAll(() => {
  if (realOffsetParent) {
    Object.defineProperty(
      HTMLElement.prototype,
      "offsetParent",
      realOffsetParent,
    );
  }
});
afterEach(cleanup);

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

const closeButton = (dialogName: string) =>
  within(screen.getByRole("dialog", { name: dialogName })).getByRole("button", {
    name: "Close dialog",
  });

describe("dialog stack: Esc (#1947)", () => {
  it("is a modal dialog labelled by its title", () => {
    render(<Stack />);
    const dlg = screen.getByRole("dialog", { name: "Outer" });
    expect(dlg.getAttribute("aria-modal")).toBe("true");
    expect(dlg.getAttribute("aria-labelledby")).toBeTruthy();
  });

  it("closes only the topmost dialog, one per press, keeping the input under it", async () => {
    const user = userEvent.setup();
    render(<Stack />);
    await user.type(screen.getByLabelText("outer-first"), "marker");
    await user.click(screen.getByText("open-inner"));
    expect(screen.getAllByRole("dialog")).toHaveLength(2);
    await user.keyboard("{Escape}");
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    expect(screen.getByRole("dialog", { name: "Outer" })).toBeTruthy();
    expect(
      (screen.getByLabelText("outer-first") as HTMLInputElement).value,
    ).toBe("marker");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("holds under StrictMode's double-run effects", async () => {
    const user = userEvent.setup();
    render(
      <StrictMode>
        <Stack />
      </StrictMode>,
    );
    await user.click(screen.getByText("open-inner"));
    await user.keyboard("{Escape}");
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    // Nothing left registered: a stale layer would swallow the next Esc.
    render(<Stack />);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("closes only a ConfirmModal opened over another dialog", async () => {
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

  it("returns focus to the opener when the top dialog closes", async () => {
    const user = userEvent.setup();
    render(<Stack />);
    const opener = screen.getByText("open-inner");
    await user.click(opener);
    await user.keyboard("{Escape}");
    expect(document.activeElement).toBe(opener);
  });
});

describe("dialog stack: focus trap (#1948)", () => {
  it("Shift+Tab from where a ConfirmModal puts focus stays inside it", async () => {
    const user = userEvent.setup();
    render(
      <>
        <button>Delete</button>
        <ConfirmModal
          open
          title="Delete policy?"
          message="x"
          confirmLabel="Delete"
          tone="destructive"
          onConfirm={() => {}}
          onClose={() => {}}
        />
      </>,
    );
    const dlg = screen.getByRole("dialog", { name: "Delete policy?" });
    expect(dlg.contains(document.activeElement)).toBe(true);
    for (let i = 0; i < 5; i++) {
      await user.tab({ shift: true });
      expect(dlg.contains(document.activeElement)).toBe(true);
    }
  });

  it("does not open with focus on a confirm's destructive button", async () => {
    const onConfirm = vi.fn();
    const user = userEvent.setup();
    render(
      <ConfirmModal
        open
        title="Permanently delete?"
        message="x"
        confirmLabel="Delete"
        tone="destructive"
        onConfirm={onConfirm}
        onClose={() => {}}
      />,
    );
    expect(document.activeElement).toBe(
      screen.getByRole("dialog", { name: "Permanently delete?" }),
    );
    await user.keyboard("{Enter}");
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("Shift+Tab from the first control wraps to the last; Tab wraps back", async () => {
    const user = userEvent.setup();
    render(<Stack />);
    await user.click(screen.getByText("open-inner"));
    closeButton("Inner").focus();
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(screen.getByLabelText("inner-last"));
    await user.tab();
    expect(document.activeElement).toBe(closeButton("Inner"));
  });

  it("Tab from the page behind comes back into the topmost dialog only", async () => {
    const user = userEvent.setup();
    render(<Stack />);
    await user.click(screen.getByText("open-inner"));
    const inner = screen.getByRole("dialog", { name: "Inner" });
    screen.getByText("page-behind").focus();
    await user.tab();
    expect(inner.contains(document.activeElement)).toBe(true);
    for (let i = 0; i < 6; i++) {
      await user.tab();
      expect(inner.contains(document.activeElement)).toBe(true);
    }
  });
});
