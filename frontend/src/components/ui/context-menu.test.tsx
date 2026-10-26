/**
 * @vitest-environment jsdom
 *
 * #2051: choosing an item that opens a dialog must leave focus in the dialog.
 * Radix returns focus to the trigger row on menu close, after the dialog took
 * it. Uses the real Radix menu and the real shared Modal.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { StrictMode, useState, type ReactNode } from "react";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuTrigger,
} from "./context-menu";
import { Modal } from "./modal";

/** A tree row with a context menu: "Delete…" opens a dialog, "Copy" does
 *  not. `afterClose` runs in the dialog's onClose. */
function Row({ afterClose }: { afterClose?: () => void }) {
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
        <ContextMenuItem onSelect={() => {}}>Copy</ContextMenuItem>
      </ContextMenuContent>
      {open && (
        <Modal
          title="Delete subnet"
          onClose={() => {
            setOpen(false);
            afterClose?.();
          }}
        >
          <button>Confirm</button>
        </Modal>
      )}
    </ContextMenu>
  );
}

/** The same row, rendered inside an already-open dialog (a tree in a picker). */
function RowInDialog() {
  return (
    <Modal title="Pick a subnet" onClose={() => {}}>
      <Row />
    </Modal>
  );
}

// jsdom lacks these; Radix's popper needs them.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver;
Element.prototype.scrollIntoView ??= () => {};

// floating-ui probes :popover-open / :modal, which nwsapi takes seconds to
// answer. jsdom has no top layer, so false is the true answer; anything else
// goes to the real implementation. Restored after this file.
const realMatches = Element.prototype.matches;
beforeAll(() => {
  Element.prototype.matches = function (sel: string) {
    if (sel === ":popover-open" || sel === ":modal") return false;
    return realMatches.call(this, sel);
  };
});
afterAll(() => {
  Element.prototype.matches = realMatches;
});

// Count live MutationObservers, so a watcher left behind is a failure.
const RealMO = globalThis.MutationObserver;
let live = 0;
class CountingMO extends RealMO {
  private on = false;
  observe(...a: Parameters<MutationObserver["observe"]>) {
    if (!this.on) live++;
    this.on = true;
    super.observe(...a);
  }
  disconnect() {
    if (this.on) live--;
    this.on = false;
    super.disconnect();
  }
}
beforeAll(() => {
  globalThis.MutationObserver = CountingMO;
});
afterAll(() => {
  globalThis.MutationObserver = RealMO;
});

const tick = () => act(() => new Promise((r) => setTimeout(r, 50)));

async function choose(row: HTMLElement, item: string) {
  // A right-button press focuses a focusable row in a browser; fireEvent
  // does not, and Radix restores focus to whatever was focused at open.
  row.focus();
  fireEvent.contextMenu(row, { clientX: 10, clientY: 10 });
  fireEvent.click(await screen.findByText(item));
  await tick();
}

afterEach(cleanup);

const wrappers: [string, (n: ReactNode) => ReactNode][] = [
  ["plain", (n) => n],
  ["StrictMode", (n) => <StrictMode>{n}</StrictMode>],
];

describe.each(wrappers)("context menu focus (%s) (#2051)", (_n, wrap) => {
  it("holds focus in the dialog, then returns it to the row on close", async () => {
    const before = live;
    render(wrap(<Row />));
    const row = screen.getByRole("treeitem");
    await choose(row, "Delete…");
    const dialog = screen.getByRole("dialog");
    expect(dialog.contains(document.activeElement)).toBe(true);

    fireEvent.keyDown(document, { key: "Escape" });
    await tick();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(row);
    expect(live).toBe(before);
  });

  it("returns focus to the row when the item opens nothing", async () => {
    const before = live;
    render(wrap(<Row />));
    const row = screen.getByRole("treeitem");
    await choose(row, "Copy");
    expect(document.activeElement).toBe(row);
    expect(live).toBe(before);
  });

  it("does not take focus back if the dialog's close placed it", async () => {
    let elsewhere: HTMLButtonElement | null = null;
    render(
      wrap(
        <>
          <button ref={(b) => void (elsewhere = b)}>elsewhere</button>
          <Row afterClose={() => elsewhere?.focus()} />
        </>,
      ),
    );
    await choose(screen.getByRole("treeitem"), "Delete…");
    fireEvent.keyDown(document, { key: "Escape" });
    await tick();
    expect(document.activeElement).toBe(elsewhere);
  });

  // A menu inside an open dialog: the host dialog was there before the menu
  // opened, so it is not one the menu launched.
  it("inside a dialog: an item that opens nothing leaves focus on the row", async () => {
    render(wrap(<RowInDialog />));
    // The host dialog watches its own content for the focused node leaving
    // (#2723); that observer lives as long as the dialog, so count from here.
    const before = live;
    const row = screen.getByRole("treeitem");
    await choose(row, "Copy");
    expect(document.activeElement).toBe(row);
    expect(live).toBe(before);
  });

  it("inside a dialog: a nested dialog keeps focus, then returns it to the row", async () => {
    render(wrap(<RowInDialog />));
    // The host dialog watches its own content for the focused node leaving
    // (#2723); that observer lives as long as the dialog, so count from here.
    const before = live;
    const row = screen.getByRole("treeitem");
    await choose(row, "Delete…");
    const nested = screen
      .getAllByRole("dialog")
      .find((d) => within(d).queryByText("Confirm"))!;
    expect(nested.contains(document.activeElement)).toBe(true);

    fireEvent.keyDown(document, { key: "Escape" });
    await tick();
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    expect(document.activeElement).toBe(row);
    expect(live).toBe(before);
  });
});
