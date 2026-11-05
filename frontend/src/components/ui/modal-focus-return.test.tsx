/**
 * @vitest-environment jsdom
 *
 * Focus return (#2050): a dialog whose field is `autoFocus`ed must still hand
 * focus back to its opener on close. The opener has to be read before React's
 * commit-time autofocus moves focus into the dialog.
 */
import { StrictMode, useState, type ReactNode } from "react";
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HeaderMenu } from "./header-menu";
import { Modal } from "./modal";

// main.tsx renders under StrictMode, whose dev-only simulated unmount runs the
// trap's cleanup once while the dialog is still on screen. Every case runs
// both ways.
const wrappers: [string, (n: ReactNode) => ReactNode][] = [
  ["plain", (n) => n],
  ["StrictMode", (n) => <StrictMode>{n}</StrictMode>],
];

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

describe.each(
  wrappers.flatMap(([name, wrap]) =>
    [true, false].map((autoFocus) => [name, wrap, autoFocus] as const),
  ),
)("focus return (%s, autoFocus=%s)", (_name, wrap, autoFocus) => {
  it("keeps the autofocused field focused while open", async () => {
    const user = userEvent.setup();
    render(wrap(<Host autoFocus={autoFocus} />));
    await user.click(screen.getByRole("button", { name: "Open it" }));
    const expected = autoFocus
      ? screen.getByRole("textbox", { name: "name" })
      : screen.getByRole("dialog");
    expect(document.activeElement).toBe(expected);
  });

  it("returns to the opener on Esc", async () => {
    const user = userEvent.setup();
    render(wrap(<Host autoFocus={autoFocus} />));
    const opener = screen.getByRole("button", { name: "Open it" });
    await user.click(opener);
    expect(screen.getByRole("dialog")).toBeTruthy();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it("returns to the opener on the close button", async () => {
    const user = userEvent.setup();
    render(wrap(<Host autoFocus={autoFocus} />));
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

function Nested() {
  const [a, setA] = useState(false);
  const [b, setB] = useState(false);
  return (
    <div>
      <button onClick={() => setA(true)}>Open A</button>
      {a && (
        <Modal title="A" onClose={() => setA(false)}>
          <input aria-label="a-field" autoFocus />
          <button onClick={() => setB(true)}>Open B</button>
          {b && (
            <Modal title="B" onClose={() => setB(false)}>
              <input aria-label="b-field" autoFocus />
            </Modal>
          )}
        </Modal>
      )}
    </div>
  );
}

it.each(wrappers)(
  "%s: a nested dialog returns to its opener inside the parent, then the parent to its own",
  async (_name, wrap) => {
    const user = userEvent.setup();
    render(wrap(<Nested />));
    const openA = screen.getByRole("button", { name: "Open A" });
    await user.click(openA);
    const openB = screen.getByRole("button", { name: "Open B" });
    await user.click(openB);
    expect(document.activeElement).toBe(
      screen.getByRole("textbox", { name: "b-field" }),
    );
    await user.keyboard("{Escape}");
    expect(document.activeElement).toBe(openB);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(openA);
  },
);

function FromMenu() {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <HeaderMenu
        label="Zone"
        items={[{ key: "edit", label: "Edit", onSelect: () => setOpen(true) }]}
      />
      {open && (
        <Modal title="Edit" onClose={() => setOpen(false)}>
          <input aria-label="edit-field" autoFocus />
        </Modal>
      )}
    </div>
  );
}

it.each(wrappers)(
  "%s: a dialog opened from a menu item returns to the menu's trigger",
  async (_name, wrap) => {
    // The item is the focused element when the dialog renders and is gone
    // with its menu by the time the dialog closes.
    const user = userEvent.setup();
    render(wrap(<FromMenu />));
    const trigger = screen.getByRole("button", { name: /Zone/ });
    await user.click(trigger);
    await user.click(screen.getByRole("menuitem", { name: "Edit" }));
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  },
);

// A dialog opened from a control inside another dialog (#3483). The control
// can leave before the inner dialog closes; where focus goes then depends on
// whether the outer dialog is still open.

function RowRemovedByInner() {
  const [a, setA] = useState(false);
  const [b, setB] = useState(false);
  const [row, setRow] = useState(true);
  return (
    <div>
      <button onClick={() => setA(true)}>Open A</button>
      {a && (
        <Modal title="A" onClose={() => setA(false)}>
          <input aria-label="a-field" />
          {row && <button onClick={() => setB(true)}>Delete row</button>}
          {b && (
            <Modal
              title="B"
              onClose={() => {
                setB(false);
                setRow(false);
              }}
            >
              <p>Delete it?</p>
            </Modal>
          )}
        </Modal>
      )}
    </div>
  );
}

it.each(wrappers)(
  "%s: an inner dialog whose opener left lands on the still-open outer dialog, not its opener behind it",
  async (_name, wrap) => {
    const user = userEvent.setup();
    render(wrap(<RowRemovedByInner />));
    await user.click(screen.getByRole("button", { name: "Open A" }));
    await user.click(screen.getByRole("button", { name: "Delete row" }));
    await user.keyboard("{Escape}");
    const outer = screen.getByRole("dialog", { name: "A" });
    expect(screen.queryByRole("dialog", { name: "B" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete row" })).toBeNull();
    expect(document.activeElement).toBe(outer);
  },
);

function MenuInsideDialog() {
  const [a, setA] = useState(false);
  const [b, setB] = useState(false);
  return (
    <div>
      <button onClick={() => setA(true)}>Open A</button>
      {a && (
        <Modal title="A" onClose={() => setA(false)}>
          <HeaderMenu
            label="Actions"
            items={[{ key: "b", label: "Open B", onSelect: () => setB(true) }]}
          />
          {b && (
            <Modal title="B" onClose={() => setB(false)}>
              <input aria-label="b-field" autoFocus />
            </Modal>
          )}
        </Modal>
      )}
    </div>
  );
}

it.each(wrappers)(
  "%s: a dialog opened from a menu inside another dialog returns to that menu's trigger",
  async (_name, wrap) => {
    const user = userEvent.setup();
    render(wrap(<MenuInsideDialog />));
    await user.click(screen.getByRole("button", { name: "Open A" }));
    const trigger = screen.getByRole("button", { name: /Actions/ });
    await user.click(trigger);
    await user.click(screen.getByRole("menuitem", { name: "Open B" }));
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog", { name: "A" })).toBeTruthy();
    expect(document.activeElement).toBe(trigger);
  },
);

/** Three dialogs, each replacing the last, each submitted from a field. */
function ThreeSteps() {
  const [step, setStep] = useState(0);
  return (
    <div>
      <button onClick={() => setStep(1)}>Start</button>
      {[1, 2].map(
        (n) =>
          step === n && (
            <Modal key={n} title={`Step ${n}`} onClose={() => setStep(0)}>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  setStep(n + 1);
                }}
              >
                <input aria-label={`field ${n}`} autoFocus />
              </form>
            </Modal>
          ),
      )}
      {step === 3 && (
        <Modal title="Step 3" onClose={() => setStep(0)}>
          <p>Done</p>
        </Modal>
      )}
    </div>
  );
}

it.each(wrappers)(
  "%s: a chain of dialogs each submitted with Enter returns to the first opener",
  async (_name, wrap) => {
    const user = userEvent.setup();
    render(wrap(<ThreeSteps />));
    const opener = screen.getByRole("button", { name: "Start" });
    await user.click(opener);
    await user.keyboard("{Enter}");
    await user.click(screen.getByRole("textbox", { name: "field 2" }));
    await user.keyboard("{Enter}");
    screen.getByRole("dialog", { name: "Step 3" });
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
  },
);
