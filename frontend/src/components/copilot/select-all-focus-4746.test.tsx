/**
 * @vitest-environment jsdom
 *
 * #4746: History's "Select all" is replaced by the bulk bar when pressed;
 * focus must move to the bar's Cancel, and Cancel hands it back (#4355).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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

let chats = [chat("a"), chat("b")];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    aiApi: {
      ...actual.aiApi,
      listSessions: () => Promise.resolve(chats.map((c) => ({ ...c }))),
      deleteSession: (id: string) => {
        chats = chats.filter((c) => c.id !== id);
        return Promise.resolve();
      },
      updateSession: (id: string) => {
        chats = chats.filter((c) => c.id !== id);
        return Promise.resolve(chat(id));
      },
      myUsage: () => Promise.resolve(null),
      listPrompts: () => Promise.resolve([]),
    },
  };
});

const { CopilotDrawer } = await import("./CopilotDrawer");

Element.prototype.scrollTo ??= () => {};

beforeEach(() => {
  chats = [chat("a"), chat("b")];
  vi.stubGlobal("confirm", () => true);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const tick = () => act(() => new Promise((r) => setTimeout(r, 50)));

async function openHistory() {
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
  return user;
}

const inDrawer = () =>
  screen
    .getByRole("dialog", { name: "Operator Copilot" })
    .contains(document.activeElement);

describe("History focus hand-offs (#4746)", () => {
  it("Select all moves focus to Cancel, and Cancel back to Select all", async () => {
    const user = await openHistory();
    screen.getByRole("button", { name: "Select all" }).focus();
    await user.keyboard("{Enter}");
    await tick();
    expect(screen.queryByRole("button", { name: "Select all" })).toBeNull();
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: "Cancel" }),
    );
    await user.keyboard("{Enter}");
    await tick();
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: "Select all" }),
    );
  });

  it("a row's Delete hands focus to Select all while chats remain", async () => {
    const user = await openHistory();
    screen.getAllByTitle("Delete")[0].focus();
    await user.keyboard("{Enter}");
    await tick();
    expect(screen.getAllByTitle("Delete")).toHaveLength(1);
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: "Select all" }),
    );
  });

  it("a row's Archive hands focus to Select all while chats remain", async () => {
    const user = await openHistory();
    screen.getAllByTitle("Archive")[0].focus();
    await user.keyboard("{Enter}");
    await tick();
    expect(screen.getAllByTitle("Archive")).toHaveLength(1);
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: "Select all" }),
    );
  });

  it("deleting the last chat hands focus to New chat", async () => {
    chats = [chat("a")];
    const user = await openHistory();
    screen.getByTitle("Delete").focus();
    await user.keyboard("{Enter}");
    await tick();
    expect(inDrawer()).toBe(true);
    expect(document.activeElement).toBe(screen.getByTitle("New chat"));
  });

  it("the bar's Delete leaves focus in the drawer (New chat once empty)", async () => {
    const user = await openHistory();
    screen.getByRole("button", { name: "Select all" }).focus();
    await user.keyboard("{Enter}");
    await tick();
    screen.getByRole("button", { name: "Delete 2" }).focus();
    await user.keyboard("{Enter}");
    await tick();
    expect(inDrawer()).toBe(true);
    expect(document.activeElement).toBe(screen.getByTitle("New chat"));
  });

  it("Delete all leaves focus in the drawer (New chat once empty)", async () => {
    const user = await openHistory();
    screen.getByRole("button", { name: "Delete all" }).focus();
    await user.keyboard("{Enter}");
    await tick();
    expect(inDrawer()).toBe(true);
    expect(document.activeElement).toBe(screen.getByTitle("New chat"));
  });
});
