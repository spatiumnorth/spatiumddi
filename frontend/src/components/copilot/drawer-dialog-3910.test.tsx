/**
 * @vitest-environment jsdom
 *
 * #3910: one Esc closes the topmost layer only (the Prompts list before the
 * drawer), closing the drawer gives focus back to what opened it, and the
 * drawer is a named dialog.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    aiApi: {
      ...actual.aiApi,
      listSessions: () => Promise.resolve([]),
      myUsage: () => Promise.resolve(null),
      listPrompts: () => Promise.resolve([]),
    },
  };
});

const { CopilotDrawer } = await import("./CopilotDrawer");

// jsdom lacks element scrolling.
Element.prototype.scrollTo ??= () => {};

afterEach(cleanup);

function Host() {
  const [open, setOpen] = useState(false);
  return (
    <QueryClientProvider client={new QueryClient()}>
      <button onClick={() => setOpen(true)}>Ask AI</button>
      {open && <CopilotDrawer onClose={() => setOpen(false)} />}
    </QueryClientProvider>
  );
}

const tick = () => act(() => new Promise((r) => setTimeout(r, 50)));

describe("Operator Copilot drawer", () => {
  it("Esc on the open Prompts list closes the list, not the drawer", async () => {
    const user = userEvent.setup();
    render(<Host />);
    await user.click(screen.getByRole("button", { name: "Ask AI" }));
    await user.click(screen.getByRole("button", { name: /Prompts/ }));
    await tick();
    expect(await screen.findByText(/No saved prompts/)).toBeTruthy();
    await user.keyboard("{Escape}");
    await tick();
    expect(
      screen.getByRole("dialog", { name: "Operator Copilot" }),
    ).toBeTruthy();
    expect(screen.getByTitle("Load a saved prompt")).toBeTruthy();
    await user.keyboard("{Escape}");
    await tick();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("closing the drawer gives focus back to Ask AI", async () => {
    const user = userEvent.setup();
    render(<Host />);
    const ask = screen.getByRole("button", { name: "Ask AI" });
    ask.focus();
    await user.keyboard("{Enter}");
    await tick();
    await user.click(screen.getByTitle("Close (Esc)"));
    await tick();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(ask);
  });
});
