/**
 * @vitest-environment jsdom
 *
 * #4111: #4009's successor fallback (the page heading) ran after the Views
 * trigger had been handed focus (#3484) and took it away, on any page that
 * has a heading. The #3484 test renders none, so it never saw it.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const views = [
  { id: "v1", page: "sites", name: "Mine", payload: {}, is_default: false },
];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    savedViewsApi: {
      list: () => Promise.resolve(views),
      create: vi.fn(),
      update: vi.fn(),
      remove: vi.fn(),
    },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { SavedViewsMenu } = await import("@/components/SavedViewsMenu");

afterEach(cleanup);

describe("Delete saved view Esc on a page with a heading (#4111)", () => {
  it("leaves focus on the Views trigger, not the heading", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <main>
          <h1>Sites</h1>
          <SavedViewsMenu page="sites" currentPayload={{}} onApply={() => {}} />
        </main>
      </QueryClientProvider>,
    );
    const user = userEvent.setup();
    const trigger = screen.getByRole("button", { name: /Views/ });
    trigger.focus();
    await user.keyboard("{Enter}");
    await screen.findByText("Mine");
    await user.tab();
    await user.tab();
    await user.tab();
    await user.keyboard("{Enter}");
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });
});
