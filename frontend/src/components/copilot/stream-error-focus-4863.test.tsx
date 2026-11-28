/**
 * @vitest-environment jsdom
 *
 * #4863: Dismiss / Retry on a failed answer remove the error block with the
 * focused button; focus must land in the question box, not the page body.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    streamChatTurn: () => ({
      [Symbol.asyncIterator]: () => ({
        next: () => Promise.reject(new Error("boom")),
      }),
    }),
    aiApi: {
      ...actual.aiApi,
      listSessions: () => Promise.resolve([]),
      myUsage: () => Promise.resolve(null),
      listPrompts: () => Promise.resolve([]),
    },
  };
});

const { CopilotDrawer } = await import("./CopilotDrawer");

Element.prototype.scrollTo ??= () => {};

afterEach(cleanup);

const tick = () => act(() => new Promise((r) => setTimeout(r, 50)));

async function failOnce(user: ReturnType<typeof userEvent.setup>) {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <CopilotDrawer onClose={() => {}} />
    </QueryClientProvider>,
  );
  await tick();
  const ta = screen.getByPlaceholderText(/Ask about IPAM/);
  await user.type(ta, "hi");
  await user.keyboard("{Control>}{Enter}{/Control}");
  await tick();
}

describe("Stream error focus (#4863)", () => {
  it("Dismiss moves focus to the question box", async () => {
    const user = userEvent.setup();
    await failOnce(user);
    const btn = screen.getByRole("button", { name: "Dismiss" });
    btn.focus();
    await user.keyboard("{Enter}");
    await tick();
    expect(screen.queryByRole("button", { name: "Dismiss" })).toBeNull();
    expect(document.activeElement?.tagName).toBe("TEXTAREA");
  });

  it("Retry moves focus to the question box", async () => {
    const user = userEvent.setup();
    await failOnce(user);
    const btn = screen.getByRole("button", { name: "Retry" });
    btn.focus();
    await user.keyboard("{Enter}");
    await tick();
    expect(document.activeElement?.tagName).toBe("TEXTAREA");
  });
});
