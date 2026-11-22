/**
 * @vitest-environment jsdom
 *
 * #4746: History's "Select all" is replaced by the bulk bar when pressed;
 * focus must move to the bar's Cancel, and Cancel hands it back (#4355).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const chat = (id: string) => ({
  id,
  name: `Chat ${id}`,
  provider_id: null,
  model: "m",
  archived_at: null,
  created_at: "2026-01-01T00:00:00Z",
  modified_at: "2026-01-01T00:00:00Z",
  message_count: 1,
});

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    aiApi: {
      ...actual.aiApi,
      listSessions: () => Promise.resolve([chat("a"), chat("b")]),
      myUsage: () => Promise.resolve(null),
      listPrompts: () => Promise.resolve([]),
    },
  };
});

const { CopilotDrawer } = await import("./CopilotDrawer");

Element.prototype.scrollTo ??= () => {};

afterEach(cleanup);

const tick = () => act(() => new Promise((r) => setTimeout(r, 50)));

describe("History Select all focus (#4746)", () => {
  it("moves focus to Cancel, and Cancel back to Select all", async () => {
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={new QueryClient()}>
        <CopilotDrawer
          onClose={() => {}}
          pendingContext={null}
          onContextConsumed={() => {}}
        />
      </QueryClientProvider>,
    );
    await tick();
    await user.click(screen.getByTitle("Recent chats"));
    await tick();
    const selectAll = screen.getByRole("button", { name: "Select all" });
    selectAll.focus();
    await user.keyboard("{Enter}");
    await tick();
    expect(screen.queryByRole("button", { name: "Select all" })).toBeNull();
    const cancel = screen.getByRole("button", { name: "Cancel" });
    expect(document.activeElement).toBe(cancel);
    await user.keyboard("{Enter}");
    await tick();
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: "Select all" }),
    );
  });
});
