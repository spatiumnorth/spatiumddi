/**
 * @vitest-environment jsdom
 *
 * #4355: "Clear context" removes the "Asking about" strip with its focused
 * button; focus must stay in the drawer (the question box), not fall to body.
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

Element.prototype.scrollTo ??= () => {};

afterEach(cleanup);

function Host() {
  const [ctx, setCtx] = useState<string | null>("Audit event: login");
  return (
    <QueryClientProvider client={new QueryClient()}>
      <CopilotDrawer
        onClose={() => {}}
        pendingContext={ctx}
        onContextConsumed={() => setCtx(null)}
      />
    </QueryClientProvider>
  );
}

const tick = () => act(() => new Promise((r) => setTimeout(r, 50)));

describe("Clear context focus (#4355)", () => {
  it("keeps focus inside the drawer after the strip is cleared", async () => {
    const user = userEvent.setup();
    render(<Host />);
    await tick();
    const clear = screen.getByRole("button", { name: "Clear context" });
    clear.focus();
    await user.keyboard("{Enter}");
    await tick();
    expect(screen.queryByRole("button", { name: "Clear context" })).toBeNull();
    const dialog = screen.getByRole("dialog", { name: "Operator Copilot" });
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(document.activeElement?.tagName).toBe("TEXTAREA");
  });
});
