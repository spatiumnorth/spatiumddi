/**
 * @vitest-environment jsdom
 *
 * #3909: after a delete the opener's button is gone, so focus goes to a
 * neighbour row (or the table), never the body.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuTrigger,
} from "./context-menu";
import { Modal } from "./modal";

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

const tick = (ms = 50) => act(() => new Promise((r) => setTimeout(r, ms)));

afterEach(cleanup);

/** Rows are plain <tr>s (no tabIndex) with an Edit button, a right-click menu
 *  and a Delete button that opens a confirm. `removeBeforeClose` removes the
 *  row first (the DNS record's refetch-then-close order); otherwise the row
 *  goes a moment after the confirm closes (the IP address order). */
function Table({ removeBeforeClose }: { removeBeforeClose?: boolean }) {
  const [rows, setRows] = useState(["a", "b", "c"]);
  const [del, setDel] = useState<string | null>(null);
  const remove = (id: string) => setRows((r) => r.filter((x) => x !== id));
  return (
    <main>
      <h1>Things</h1>
      <table>
        <tbody>
          {rows.map((id) => (
            <ContextMenu key={id}>
              <ContextMenuTrigger asChild>
                <tr>
                  <td>
                    <button aria-label={"Edit " + id}>edit</button>
                    <button
                      aria-label={"Delete " + id}
                      onClick={() => setDel(id)}
                    >
                      del
                    </button>
                  </td>
                </tr>
              </ContextMenuTrigger>
              <ContextMenuContent>
                <ContextMenuItem onSelect={() => setDel(id)}>
                  Delete…
                </ContextMenuItem>
              </ContextMenuContent>
            </ContextMenu>
          ))}
        </tbody>
      </table>
      {del && (
        <Modal title="Delete thing" onClose={() => setDel(null)}>
          <button
            onClick={() => {
              const id = del;
              if (removeBeforeClose) {
                remove(id);
                setDel(null);
              } else {
                setDel(null);
                setTimeout(() => remove(id), 20);
              }
            }}
          >
            Confirm
          </button>
        </Modal>
      )}
    </main>
  );
}

describe("focus after a delete (#3909)", () => {
  it("moves focus to the next row when the row goes just after the close", async () => {
    const user = userEvent.setup();
    render(<Table />);
    await user.click(screen.getByRole("button", { name: "Delete a" }));
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    await tick(100);
    expect(screen.queryByRole("button", { name: "Delete a" })).toBeNull();
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: "Delete b" }),
    );
  });

  it("moves focus to a neighbour when the opener was gone at the close", async () => {
    const user = userEvent.setup();
    render(<Table removeBeforeClose />);
    await user.click(screen.getByRole("button", { name: "Delete c" }));
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    await tick(100);
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: "Delete b" }),
    );
  });

  it("falls back to the table when the last row goes", async () => {
    const user = userEvent.setup();
    render(<Table removeBeforeClose />);
    for (const id of ["a", "b", "c"]) {
      await user.click(screen.getByRole("button", { name: "Delete " + id }));
      await user.click(screen.getByRole("button", { name: "Confirm" }));
      await tick(100);
    }
    expect(document.activeElement).not.toBe(document.body);
    expect(document.activeElement?.tagName).toBe("TABLE");
  });
});
