/**
 * @vitest-environment jsdom
 *
 * #4221: after a delete from a card list or a tree, the opener's control is
 * removed by the refetch with focus on it; focus goes to the next card or tree
 * item, never the page body. The watcher used to run only for tr / li rows.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuTrigger,
} from "./context-menu";
import { Modal } from "./modal";

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver;
Element.prototype.scrollIntoView ??= () => {};

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

function Confirm({
  del,
  setDel,
  remove,
}: {
  del: string;
  setDel: (v: string | null) => void;
  remove: (id: string) => void;
}) {
  return (
    <Modal title="Delete thing" onClose={() => setDel(null)}>
      <button
        onClick={() => {
          setDel(null);
          setTimeout(() => remove(del), 20);
        }}
      >
        Confirm
      </button>
    </Modal>
  );
}

function Cards({ initial = ["a", "b", "c"] }: { initial?: string[] }) {
  const [items, setItems] = useState(initial);
  const [del, setDel] = useState<string | null>(null);
  return (
    <main>
      <h1>Views</h1>
      <div data-testid="list">
        {items.map((id) => (
          <div key={id} className="card">
            <span>{id}</span>
            <button aria-label={"Delete " + id} onClick={() => setDel(id)}>
              del
            </button>
          </div>
        ))}
      </div>
      {del && (
        <Confirm
          del={del}
          setDel={setDel}
          remove={(x) => setItems((r) => r.filter((i) => i !== x))}
        />
      )}
    </main>
  );
}

function Tree() {
  const [items, setItems] = useState(["a", "b", "c"]);
  const [del, setDel] = useState<string | null>(null);
  return (
    <main>
      <h1>Tree</h1>
      <div role="tree">
        <div role="group">
          {items.map((id) => (
            <ContextMenu key={id}>
              <ContextMenuTrigger asChild>
                <div role="treeitem" aria-label={id} tabIndex={0}>
                  {id}
                </div>
              </ContextMenuTrigger>
              <ContextMenuContent>
                <ContextMenuItem onSelect={() => setDel(id)}>
                  Delete…
                </ContextMenuItem>
              </ContextMenuContent>
            </ContextMenu>
          ))}
        </div>
      </div>
      {del && (
        <Confirm
          del={del}
          setDel={setDel}
          remove={(x) => setItems((r) => r.filter((i) => i !== x))}
        />
      )}
    </main>
  );
}

describe("focus after a delete from a card or a tree (#4221)", () => {
  it("a card's Delete hands focus to the next card's Delete", async () => {
    const user = userEvent.setup();
    render(<Cards />);
    await user.click(screen.getByRole("button", { name: "Delete a" }));
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    await tick(100);
    expect(screen.queryByRole("button", { name: "Delete a" })).toBeNull();
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: "Delete b" }),
    );
  });

  it("the last card falls back to the list, not the body", async () => {
    const user = userEvent.setup();
    render(<Cards />);
    for (const id of ["a", "b", "c"]) {
      await user.click(screen.getByRole("button", { name: "Delete " + id }));
      await user.click(screen.getByRole("button", { name: "Confirm" }));
      await tick(100);
    }
    expect(document.activeElement).not.toBe(document.body);
    expect(document.activeElement?.closest("main")).not.toBeNull();
  });

  it("deleting the only card focuses the list, not main (#4224)", async () => {
    const user = userEvent.setup();
    render(<Cards initial={["a"]} />);
    await user.click(screen.getByRole("button", { name: "Delete a" }));
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    await tick(100);
    expect(screen.queryByRole("button", { name: "Delete a" })).toBeNull();
    expect(document.activeElement).toBe(screen.getByTestId("list"));
  });

  it("deleting the bottom card of two focuses the previous card's Delete (#4224)", async () => {
    const user = userEvent.setup();
    render(<Cards initial={["a", "b"]} />);
    await user.click(screen.getByRole("button", { name: "Delete b" }));
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    await tick(100);
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: "Delete a" }),
    );
  });

  it("a tree item deleted from its menu hands focus to the next item", async () => {
    const user = userEvent.setup();
    render(<Tree />);
    const item = screen.getByRole("treeitem", { name: "b" });
    item.focus();
    fireEvent.contextMenu(item);
    await user.click(await screen.findByRole("menuitem", { name: "Delete…" }));
    await user.click(await screen.findByRole("button", { name: "Confirm" }));
    await tick(150);
    expect(screen.queryByRole("treeitem", { name: "b" })).toBeNull();
    expect(document.activeElement).toBe(
      screen.getByRole("treeitem", { name: "c" }),
    );
  });
});
