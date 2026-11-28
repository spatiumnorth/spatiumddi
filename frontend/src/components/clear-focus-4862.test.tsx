/**
 * @vitest-environment jsdom
 *
 * A control that removes itself (a selection bar's Clear, a filter's Clear,
 * a tag chip's Remove) leaves keyboard focus on a control in the page, never
 * the body (#4862).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { handOffFocusOnRemove } from "@/components/ui/focus-return";

vi.mock("@/lib/api", async (orig) => ({
  ...((await orig()) as object),
  tagsApi: {
    listKeys: vi.fn().mockResolvedValue({ keys: [] }),
    listValues: vi.fn().mockResolvedValue({ values: [] }),
  },
}));
const { TagFilterChips } = await import("@/components/TagFilterChips");

afterEach(cleanup);

function Bar() {
  const [sel, setSel] = useState(true);
  return (
    <main>
      {sel && (
        <div>
          <button
            onClick={(e) => {
              handOffFocusOnRemove(e.currentTarget);
              setSel(false);
            }}
          >
            Clear
          </button>
        </div>
      )}
      <table>
        <tbody>
          <tr>
            <td>
              <input type="checkbox" aria-label="all" />
            </td>
          </tr>
        </tbody>
      </table>
    </main>
  );
}

describe("self-removing controls keep focus in the page (#4862)", () => {
  it("a selection bar's Clear hands focus to the table's check box", async () => {
    render(<Bar />);
    const user = userEvent.setup();
    await user.tab();
    expect(document.activeElement).toBe(screen.getByText("Clear"));
    await user.keyboard("{Enter}");
    expect(screen.queryByText("Clear")).toBeNull();
    expect(document.activeElement).toBe(screen.getByLabelText("all"));
  });

  it("a tag chip's Remove hands focus to the filter's textbox", async () => {
    function H() {
      const [v, setV] = useState(["env"]);
      return (
        <QueryClientProvider client={new QueryClient()}>
          <TagFilterChips value={v} onChange={setV} />
        </QueryClientProvider>
      );
    }
    render(<H />);
    const user = userEvent.setup();
    screen.getByTitle('Remove "env"').focus();
    await user.keyboard("{Enter}");
    expect(screen.queryByTitle('Remove "env"')).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("textbox"));
  });
});
