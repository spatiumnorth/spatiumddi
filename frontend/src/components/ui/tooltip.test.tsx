/**
 * @vitest-environment jsdom
 *
 * TooltipLayer (#4210) — the 300 ms replacement for the native `title`
 * tooltip. Pinned: not before the delay, native title out of the way
 * while shown and back after, keyboard focus at once, Esc, a disabled
 * button's reason, and the same inside a dialog.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { Modal } from "./modal";
import { TooltipLayer } from "./tooltip";

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

const hover = (el: Element) =>
  fireEvent.pointerOver(el, { pointerType: "mouse" });
const tick = (ms: number) => act(() => void vi.advanceTimersByTime(ms));

function Page() {
  return (
    <>
      <TooltipLayer />
      <button title="Edit zone">E</button>
      <button title="Icon only" data-testid="icon">
        <svg />
      </button>
      <button aria-label="Delete" title="Delete the zone">
        <svg />
      </button>
      <button title="Needs write access" disabled>
        Save
      </button>
      <span title="">plain</span>
    </>
  );
}

describe("TooltipLayer", () => {
  it("shows the title after ~300 ms, not before; suppresses and restores the native title", () => {
    render(<Page />);
    const btn = screen.getByText("E");
    hover(btn);
    tick(250);
    expect(screen.queryByRole("tooltip")).toBeNull();
    tick(60);
    const tip = screen.getByRole("tooltip");
    expect(tip.textContent).toBe("Edit zone");
    expect(btn.getAttribute("aria-describedby")).toBe(tip.id);
    expect(btn.hasAttribute("title")).toBe(false);
    fireEvent.pointerOver(document.body, { pointerType: "mouse" });
    expect(screen.queryByRole("tooltip")).toBeNull();
    expect(btn.getAttribute("title")).toBe("Edit zone");
    expect(btn.hasAttribute("aria-describedby")).toBe(false);
  });

  it("keeps a title-only control's accessible name while shown", () => {
    render(<Page />);
    const btn = screen.getByTestId("icon");
    hover(btn);
    tick(300);
    expect(btn.getAttribute("aria-label")).toBe("Icon only");
    fireEvent.pointerOver(document.body, { pointerType: "mouse" });
    expect(btn.hasAttribute("aria-label")).toBe(false);
  });

  it("never overrides an existing aria-label", () => {
    render(<Page />);
    const btn = screen.getByLabelText("Delete");
    hover(btn);
    tick(300);
    expect(btn.getAttribute("aria-label")).toBe("Delete");
  });

  it("keyboard focus shows it immediately and Esc hides it", () => {
    render(<Page />);
    const btn = screen.getByText("E");
    act(() => btn.focus());
    expect(screen.getByRole("tooltip").textContent).toBe("Edit zone");
    fireEvent.keyDown(document.body, { key: "Escape" });
    expect(screen.queryByRole("tooltip")).toBeNull();
    expect(btn.getAttribute("title")).toBe("Edit zone");
  });

  it("hides on blur and on scroll", () => {
    render(<Page />);
    const btn = screen.getByText("E");
    act(() => btn.focus());
    act(() => btn.blur());
    expect(screen.queryByRole("tooltip")).toBeNull();
    hover(btn);
    tick(300);
    fireEvent.scroll(window);
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("shows a disabled button's reason via hit-testing", () => {
    render(<Page />);
    const dis = screen.getByText("Save");
    // jsdom has no layout; stand in for the browser's hit test.
    document.elementsFromPoint = () => [dis, document.body];
    // The event lands on an untitled ancestor, as in browsers that
    // swallow pointer events on disabled controls.
    fireEvent.pointerMove(document.body, {
      pointerType: "mouse",
      clientX: 5,
      clientY: 5,
    });
    tick(300);
    expect(screen.getByRole("tooltip").textContent).toBe("Needs write access");
    // @ts-expect-error cleanup of the stub
    delete document.elementsFromPoint;
  });

  it("ignores an empty title", () => {
    render(<Page />);
    hover(screen.getByText("plain"));
    tick(400);
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("does not reappear after a click until the pointer leaves", () => {
    render(<Page />);
    const btn = screen.getByText("E");
    hover(btn);
    tick(300);
    fireEvent.pointerDown(btn);
    expect(screen.queryByRole("tooltip")).toBeNull();
    fireEvent.pointerMove(btn, { pointerType: "mouse" });
    tick(400);
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("works inside a dialog", () => {
    function Host() {
      return (
        <>
          <TooltipLayer />
          <Modal onClose={() => {}} title="Dlg">
            <button title="Inside dialog">x</button>
          </Modal>
        </>
      );
    }
    render(<Host />);
    hover(screen.getByText("x"));
    tick(300);
    expect(screen.getByRole("tooltip").textContent).toBe("Inside dialog");
  });
});
