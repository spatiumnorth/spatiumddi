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

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    searchApi: {
      search: () =>
        Promise.resolve({
          total: 1,
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

function setup() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <GlobalSearch />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return userEvent.setup();
}

afterEach(() => cleanup());

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
  });
});
