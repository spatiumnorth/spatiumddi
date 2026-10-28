/**
 * @vitest-environment jsdom
 *
 * The global search palette is a named, modal dialog that holds focus (#1949).
 *
 * Ctrl/Cmd+K opened a full-screen overlay with no role, no name and no trap:
 * a screen reader was never told a modal opened, Tab and Shift+Tab walked out
 * to the page behind, and page code asking "is a dialog open?" (the `?`
 * shortcut's stacking guard) could not see it. Driven with real key events.
 */

import { useState, type ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const mockMeta = vi.hoisted(() => ({
  total: 1,
  total_capped: false as boolean,
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    searchApi: {
      search: () =>
        Promise.resolve({
          total: mockMeta.total,
          total_capped: mockMeta.total_capped,
          results: [
            {
              type: "subnet",
              id: "s1",
              display: "10.0.0.0/24",
              name: "lab",
            },
          ],
        }),
      types: () =>
        Promise.resolve([
          { type: "subnet", group: "ipam" },
          { type: "dns_zone", group: "dns" },
        ]),
    },
  };
});
vi.mock("@/components/copilot/useAiAvailable", () => ({
  useAiAvailable: () => false,
}));
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true, ready: true }),
}));

const { GlobalSearch } = await import("@/components/GlobalSearch");
const { KeyboardShortcutsHelp } =
  await import("@/components/KeyboardShortcutsOverlay");
const { Modal } = await import("@/components/ui/modal");

function EditDialog() {
  const [open, setOpen] = useState(true);
  return open ? (
    <Modal title="Edit thing" onClose={() => setOpen(false)}>
      <input aria-label="dialog-field" />
      <button type="button">dialog-save</button>
    </Modal>
  ) : null;
}

function setup(extra?: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <button type="button">page-behind</button>
        <GlobalSearch />
        {extra}
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return userEvent.setup();
}

async function openWithKeyboard(user: ReturnType<typeof userEvent.setup>) {
  await user.keyboard("{Control>}k{/Control}");
  const dialog = await screen.findByRole("dialog", { name: "Search" });
  const box = within(dialog).getByRole("combobox", { name: "Search" });
  await vi.waitFor(() => expect(document.activeElement).toBe(box));
  return { dialog, box };
}

afterEach(() => {
  cleanup();
  mockMeta.total = 1;
  mockMeta.total_capped = false;
});

describe("global search palette", () => {
  it("opens as a named, modal dialog around the search box", async () => {
    const user = setup();
    await user.keyboard("{Control>}k{/Control}");
    const dialog = await screen.findByRole("dialog", { name: "Search" });
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    const box = screen.getByRole("combobox", { name: "Search" });
    expect(dialog.contains(box)).toBe(true);
  });

  it("keeps Tab and Shift+Tab inside the dialog", async () => {
    const user = setup();
    await user.keyboard("{Control>}k{/Control}");
    const dialog = await screen.findByRole("dialog", { name: "Search" });
    await vi.waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByRole("combobox", { name: "Search" }),
      ),
    );
    await user.keyboard("{Shift>}{Tab}{/Shift}");
    expect(dialog.contains(document.activeElement)).toBe(true);
    for (let i = 0; i < 12; i++) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
    for (let i = 0; i < 12; i++) {
      await user.tab({ shift: true });
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });

  it("closes on Esc and returns focus to the opener", async () => {
    const user = setup();
    const trigger = screen.getByRole("button", { name: /Search or jump to/ });
    await user.click(trigger);
    await screen.findByRole("dialog", { name: "Search" });
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  it("exposes the results as a listbox the combobox points into", async () => {
    const user = setup();
    await user.keyboard("{Control>}k{/Control}");
    const box = await screen.findByRole("combobox", { name: "Search" });
    await vi.waitFor(() => expect(document.activeElement).toBe(box));
    await user.keyboard("10.0");
    const option = await screen.findByRole("option", {
      name: /10\.0\.0\.0\/24/,
    });
    expect(box.getAttribute("aria-controls")).toBe(
      screen.getByRole("listbox").id,
    );
    expect(box.getAttribute("aria-activedescendant")).toBe(option.id);
    expect(option.getAttribute("aria-selected")).toBe("true");
  });

  it("names the clear-query button", async () => {
    const user = setup();
    await user.keyboard("{Control>}k{/Control}");
    const box = await screen.findByRole("combobox");
    await vi.waitFor(() => expect(document.activeElement).toBe(box));
    await user.keyboard("abc");
    await user.click(
      await screen.findByRole("button", { name: "Clear search" }),
    );
    expect((screen.getByRole("combobox") as HTMLInputElement).value).toBe("");
    // Clearing hands focus back to the box, so the next keystroke types.
    expect(document.activeElement).toBe(screen.getByRole("combobox"));
  });

  it("returns focus to what had it when Ctrl+K opened the palette", async () => {
    const user = setup();
    const behind = screen.getByRole("button", { name: "page-behind" });
    behind.focus();
    await openWithKeyboard(user);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(behind);
  });

  it("brings Tab back in when focus has left the card", async () => {
    const user = setup();
    const { dialog } = await openWithKeyboard(user);
    // A click on the card's padding leaves focus on <body>.
    (document.activeElement as HTMLElement).blur();
    expect(document.activeElement).toBe(document.body);
    await user.tab();
    expect(dialog.contains(document.activeElement)).toBe(true);
    (document.activeElement as HTMLElement).blur();
    await user.tab({ shift: true });
    expect(dialog.contains(document.activeElement)).toBe(true);
  });

  it("over an open dialog, owns Tab and Esc, then hands focus back to it", async () => {
    const user = setup(<EditDialog />);
    const edit = screen.getByRole("dialog", { name: "Edit thing" });
    const field = within(edit).getByRole("textbox", { name: "dialog-field" });
    field.focus();
    const { dialog } = await openWithKeyboard(user);
    // Exactly one trap acts: the dialog underneath must not pull focus
    // back into itself, and the palette must not let it out.
    for (let i = 0; i < 10; i++) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
    for (let i = 0; i < 10; i++) {
      await user.tab({ shift: true });
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Search" })).toBeNull();
    expect(screen.getByRole("dialog", { name: "Edit thing" })).toBeTruthy();
    expect(document.activeElement).toBe(field);
  });

  it("is seen as an open dialog, so ? does not open Keyboard shortcuts over it", async () => {
    const user = setup(<KeyboardShortcutsHelp />);
    const { dialog } = await openWithKeyboard(user);
    // From a chip, not the box: "?" typed into the box is just a character.
    within(dialog).getByRole("button", { name: "All" }).focus();
    await user.keyboard("?");
    expect(
      screen.queryByRole("dialog", { name: "Keyboard shortcuts" }),
    ).toBeNull();
  });

  it("keeps the status text out of the listbox", async () => {
    const user = setup();
    await openWithKeyboard(user);
    const listbox = screen.getByRole("listbox");
    expect(within(listbox).queryByText(/Search IP addresses/)).toBeNull();
    expect(screen.getByText(/Search IP addresses/)).toBeTruthy();
  });

  it("footer shows the API's match count, not the rows fetched (#2987)", async () => {
    mockMeta.total = 25;
    const user = setup();
    await user.keyboard("{Control>}k{/Control}");
    const box = await screen.findByRole("combobox", { name: "Search" });
    await user.type(box, "10.0");
    await screen.findByRole("option", { name: /10\.0\.0\.0\/24/ });
    expect(await screen.findByText(/25 results · showing top 1/)).toBeTruthy();
  });

  it("footer says the count is a floor when the server capped it (#2987)", async () => {
    mockMeta.total = 100;
    mockMeta.total_capped = true;
    const user = setup();
    await user.keyboard("{Control>}k{/Control}");
    const box = await screen.findByRole("combobox", { name: "Search" });
    await user.type(box, "10.0");
    await screen.findByRole("option", { name: /10\.0\.0\.0\/24/ });
    expect(
      await screen.findByText(/100\+ results · showing top 1/),
    ).toBeTruthy();
  });
});
