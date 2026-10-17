/**
 * @vitest-environment jsdom
 *
 * #2051: choosing an item that opens a dialog must leave focus in the dialog.
 * Radix returns focus to the trigger row on menu close, after the dialog took
 * it. Uses the real Radix menu and the real shared Modal.
 */
import { afterEach, describe, expect, it } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { useState } from "react";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuTrigger,
} from "./context-menu";
import { Modal } from "./modal";

function Harness() {
  const [open, setOpen] = useState(false);
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>
        <div role="treeitem" tabIndex={0} aria-label="10.0.0.0/24">
          row
        </div>
      </ContextMenuTrigger>
      <ContextMenuContent>
        <ContextMenuItem onSelect={() => setOpen(true)}>
          Delete…
        </ContextMenuItem>
      </ContextMenuContent>
      {open && (
        <Modal title="Delete subnet" onClose={() => setOpen(false)}>
          <button>Confirm</button>
        </Modal>
      )}
    </ContextMenu>
  );
}

// jsdom lacks these; Radix's popper needs them.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver;
Element.prototype.scrollIntoView ??= () => {};

// floating-ui probes :popover-open / :modal; nwsapi answers those in ~seconds.
const realMatches = Element.prototype.matches;
Element.prototype.matches = function (sel: string) {
  if (sel === ":popover-open" || sel === ":modal") return false;
  return realMatches.call(this, sel);
};

const tick = () => act(() => new Promise((r) => setTimeout(r, 50)));

afterEach(cleanup);

describe("context menu launching a dialog (#2051)", () => {
  it("holds focus in the dialog, then returns it to the row on close", async () => {
    render(<Harness />);
    const row = screen.getByRole("treeitem");
    fireEvent.contextMenu(row, { clientX: 10, clientY: 10 });
    fireEvent.click(await screen.findByText("Delete…"));
    await tick();
    const dialog = screen.getByRole("dialog");
    expect(dialog.contains(document.activeElement)).toBe(true);

    fireEvent.keyDown(document, { key: "Escape" });
    await tick();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(row);
  });
});
