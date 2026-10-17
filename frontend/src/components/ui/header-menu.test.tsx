/**
 * @vitest-environment jsdom
 *
 * HeaderMenu (#996) — the dropdown two detail headers now depend on.
 *
 * The DNS zone detail had eleven peer buttons in a non-wrapping row and
 * clipped its own primary action; folding the once-per-zone ones into
 * menus is the fix. That makes this primitive load-bearing for actions
 * an operator can no longer reach any other way, so the failure modes
 * worth pinning are the ones review and `tsc` both pass over: an arrow
 * key that does not wrap, a disabled item that still takes focus (or
 * still fires), a trigger rendered for a menu with nothing in it.
 *
 * It also carries IPAM's `SyncMenu`, which was a local copy of the same
 * open-state dance — so a regression here is two surfaces, not one.
 */

import { describe, expect, it, vi, afterEach } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { HeaderMenu, type HeaderMenuItem } from "./header-menu";

afterEach(cleanup);

const item = (over: Partial<HeaderMenuItem> = {}): HeaderMenuItem => ({
  key: "a",
  label: "Alpha",
  onSelect: vi.fn(),
  ...over,
});

function openMenu(label = "Zone") {
  fireEvent.click(screen.getByRole("button", { name: new RegExp(label) }));
}

describe("open / close", () => {
  it("renders no panel until the trigger is clicked", () => {
    render(<HeaderMenu label="Zone" items={[item()]} />);
    expect(screen.queryByRole("menu")).toBeNull();
    openMenu();
    expect(screen.getByRole("menu")).toBeTruthy();
  });

  it("closes on Escape and returns focus to the trigger", () => {
    render(<HeaderMenu label="Zone" items={[item()]} />);
    const trigger = screen.getByRole("button", { name: /Zone/ });
    openMenu();
    fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
    // Returning focus is what makes the menu usable without a mouse —
    // without it, Escape drops focus to <body> and the next Tab
    // restarts from the top of the page.
    expect(document.activeElement).toBe(trigger);
  });

  it("closes on Escape after a mouse open, focus still on the trigger (#2047)", () => {
    render(<HeaderMenu label="Zone" items={[item()]} />);
    const trigger = screen.getByRole("button", { name: /Zone/ });
    trigger.focus();
    openMenu();
    // Mouse open: focus never moved into the panel.
    expect(document.activeElement).toBe(trigger);
    fireEvent.keyDown(trigger, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  it("closes on Escape pressed on <body> and does not reach a window handler", () => {
    const onWindow = vi.fn();
    window.addEventListener("keydown", onWindow);
    render(<HeaderMenu label="Zone" items={[item()]} />);
    openMenu();
    fireEvent.keyDown(document.body, { key: "Escape" });
    window.removeEventListener("keydown", onWindow);
    expect(screen.queryByRole("menu")).toBeNull();
    expect(onWindow).not.toHaveBeenCalled();
  });

  it("does not swallow Escape while the menu is closed", () => {
    const onWindow = vi.fn();
    window.addEventListener("keydown", onWindow);
    render(<HeaderMenu label="Zone" items={[item()]} />);
    const trigger = screen.getByRole("button", { name: /Zone/ });
    trigger.focus();
    fireEvent.keyDown(trigger, { key: "Escape" });
    window.removeEventListener("keydown", onWindow);
    expect(onWindow).toHaveBeenCalledOnce();
  });

  it("closes on an outside mousedown", () => {
    render(<HeaderMenu label="Zone" items={[item()]} />);
    openMenu();
    fireEvent.mouseDown(document.body);
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("closes when an item is chosen, and runs it", () => {
    const onSelect = vi.fn();
    render(<HeaderMenu label="Zone" items={[item({ onSelect })]} />);
    openMenu();
    fireEvent.click(screen.getByRole("menuitem", { name: "Alpha" }));
    expect(onSelect).toHaveBeenCalledOnce();
    expect(screen.queryByRole("menu")).toBeNull();
  });
});

describe("empty and fully-disabled menus", () => {
  it("renders nothing at all for an empty item list", () => {
    // A forward DNS zone stores no records, so its Data menu collapses
    // to nothing. A trigger that opens an empty panel is worse than the
    // row it replaced.
    const { container } = render(<HeaderMenu label="Data" items={[]} />);
    expect(container.innerHTML).toBe("");
  });

  it("disables the trigger when every item is disabled", () => {
    render(<HeaderMenu label="Zone" items={[item({ disabled: true })]} />);
    expect(
      screen.getByRole("button", { name: /Zone/ }).hasAttribute("disabled"),
    ).toBe(true);
  });
});

describe("per-item state carries over from the row", () => {
  it("keeps the disabled reason as a tooltip and refuses the click", () => {
    // The Tailscale-owned-zone lock and the forward-zone gating are
    // both "disabled WITH a reason". Losing the reason on the way into
    // a menu would leave an operator with a dead item and no
    // explanation.
    const onSelect = vi.fn();
    render(
      <HeaderMenu
        label="Zone"
        items={[
          item({
            disabled: true,
            title: "Records are managed by the Tailscale reconciler.",
            onSelect,
          }),
          item({ key: "b", label: "Beta" }),
        ]}
      />,
    );
    openMenu();
    const alpha = screen.getByRole("menuitem", { name: "Alpha" });
    expect(alpha.getAttribute("title")).toMatch(/Tailscale/);
    fireEvent.click(alpha);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("styles a destructive item apart and can put a separator above it", () => {
    render(
      <HeaderMenu
        label="Zone"
        items={[
          item(),
          item({
            key: "del",
            label: "Delete Zone",
            destructive: true,
            separatorBefore: true,
          }),
        ]}
      />,
    );
    openMenu();
    expect(
      screen
        .getByRole("menuitem", { name: "Delete Zone" })
        .className.includes("text-destructive"),
    ).toBe(true);
    expect(screen.getByRole("menu").querySelectorAll(".border-t").length).toBe(
      1,
    );
  });

  it("preserves the declared item order", () => {
    render(
      <HeaderMenu
        label="Zone"
        items={[
          item({ key: "1", label: "First" }),
          item({ key: "2", label: "Second" }),
          item({ key: "3", label: "Third" }),
        ]}
      />,
    );
    openMenu();
    expect(screen.getAllByRole("menuitem").map((n) => n.textContent)).toEqual([
      "First",
      "Second",
      "Third",
    ]);
  });
});

describe("keyboard navigation", () => {
  const three = [
    item({ key: "1", label: "First" }),
    item({ key: "2", label: "Second" }),
    item({ key: "3", label: "Third" }),
  ];

  it("opens on ArrowDown and focuses the first item", async () => {
    render(<HeaderMenu label="Zone" items={three} />);
    fireEvent.keyDown(screen.getByRole("button", { name: /Zone/ }), {
      key: "ArrowDown",
    });
    // Focus is scheduled after the panel mounts.
    await vi.waitFor(() =>
      expect(document.activeElement?.textContent).toBe("First"),
    );
  });

  it("wraps at both ends", async () => {
    render(<HeaderMenu label="Zone" items={three} />);
    fireEvent.keyDown(screen.getByRole("button", { name: /Zone/ }), {
      key: "Enter",
    });
    await vi.waitFor(() =>
      expect(document.activeElement?.textContent).toBe("First"),
    );
    const menu = screen.getByRole("menu");
    // Up from the first lands on the last — the arithmetic that a
    // hand-rolled copy gets wrong, and that reads as "the key does
    // nothing" rather than as an error.
    fireEvent.keyDown(menu, { key: "ArrowUp" });
    expect(document.activeElement?.textContent).toBe("Third");
    fireEvent.keyDown(menu, { key: "ArrowDown" });
    expect(document.activeElement?.textContent).toBe("First");
  });

  it("Home and End jump to the ends", async () => {
    render(<HeaderMenu label="Zone" items={three} />);
    fireEvent.keyDown(screen.getByRole("button", { name: /Zone/ }), {
      key: "ArrowDown",
    });
    await vi.waitFor(() =>
      expect(document.activeElement?.textContent).toBe("First"),
    );
    const menu = screen.getByRole("menu");
    fireEvent.keyDown(menu, { key: "End" });
    expect(document.activeElement?.textContent).toBe("Third");
    fireEvent.keyDown(menu, { key: "Home" });
    expect(document.activeElement?.textContent).toBe("First");
  });

  it("skips disabled items rather than focusing them", async () => {
    render(
      <HeaderMenu
        label="Zone"
        items={[
          item({ key: "1", label: "First" }),
          item({ key: "2", label: "Second", disabled: true }),
          item({ key: "3", label: "Third" }),
        ]}
      />,
    );
    fireEvent.keyDown(screen.getByRole("button", { name: /Zone/ }), {
      key: "ArrowDown",
    });
    await vi.waitFor(() =>
      expect(document.activeElement?.textContent).toBe("First"),
    );
    fireEvent.keyDown(screen.getByRole("menu"), { key: "ArrowDown" });
    expect(document.activeElement?.textContent).toBe("Third");
  });
});

describe("badge", () => {
  it("surfaces an advisory that would otherwise be lost inside the menu", () => {
    // Delegate is a nudge: the parent zone is missing NS / glue. Hiding
    // it in a menu without a marker on the trigger loses the nudge,
    // which is the one real cost of folding a row into menus.
    render(
      <HeaderMenu
        label="Zone"
        items={[item()]}
        badge
        badgeTitle="The parent zone is missing NS / glue records."
      />,
    );
    expect(screen.getByLabelText(/missing NS \/ glue/)).toBeTruthy();
  });

  it("shows no badge by default", () => {
    render(<HeaderMenu label="Zone" items={[item()]} />);
    expect(screen.queryByLabelText(/missing/)).toBeNull();
  });
});
