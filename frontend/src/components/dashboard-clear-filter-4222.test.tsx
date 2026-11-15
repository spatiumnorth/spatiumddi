/**
 * @vitest-environment jsdom
 *
 * The Dashboard Spaces filter's Clear filter removes itself (it is drawn only
 * while a filter is set); focus goes to the filter button and the list
 * closes, never the page body (#4222).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import type { IPSpace } from "@/lib/api";

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { IpamSpaceFilter } = await import("@/pages/DashboardPage");

afterEach(cleanup);

const spaces = [
  { id: "a", name: "Alpha" },
  { id: "b", name: "Beta" },
] as IPSpace[];

function Harness() {
  const [sel, setSel] = useState<string[]>([]);
  return <IpamSpaceFilter spaces={spaces} selected={sel} onChange={setSel} />;
}

describe("Dashboard Spaces filter, Clear filter (#4222)", () => {
  it("hands focus to the filter button and closes the list", async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <Harness />
      </QueryClientProvider>,
    );
    const user = userEvent.setup();
    const btn = screen.getByRole("button", { name: /Spaces: All/ });
    btn.focus();
    await user.keyboard("{Enter}");
    await user.click(screen.getByRole("checkbox", { name: /Alpha/ }));
    const clear = screen.getByRole("button", { name: "Clear filter" });
    clear.focus();
    await user.keyboard("{Enter}");
    expect(screen.queryByRole("button", { name: "Clear filter" })).toBeNull();
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: /Spaces: All/ }),
    );
    expect(screen.queryByText("Beta")).toBeNull();
  });
});
