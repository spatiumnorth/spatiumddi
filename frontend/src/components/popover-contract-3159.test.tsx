/**
 * @vitest-environment jsdom
 *
 * The pickers that sit outside HeaderMenu close under the same contract
 * (#3159): Esc closes however it was opened and returns focus to the
 * button, a press elsewhere closes, and focus moving to another menu
 * closes it, so two are never open at once.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import type { IPSpace } from "@/lib/api";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    savedViewsApi: {
      list: () => Promise.resolve([]),
      create: vi.fn(),
      update: vi.fn(),
      remove: vi.fn(),
    },
    ipamApi: {
      ...actual.ipamApi,
      blockAggregationSuggestions: () =>
        Promise.resolve([
          {
            supernet: "10.0.0.0/23",
            prefix_len: 23,
            total_size: 512,
            subnet_ids: ["a", "b"],
            subnet_networks: ["10.0.0.0/24", "10.0.1.0/24"],
            candidate_key: "k1",
            snoozed_until: null,
          },
        ]),
    },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

const { FilterModePicker } = await import("@/components/ui/filter-mode-picker");
const { SavedViewsMenu } = await import("@/components/SavedViewsMenu");
const { AggregationCandidatesBadge } =
  await import("@/components/ipam/AggregationSuggestions");
const { IpamSpaceFilter } = await import("@/pages/DashboardPage");
const { HeaderMenu } = await import("@/components/ui/header-menu");

afterEach(cleanup);

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

const spaces = [
  { id: "s1", name: "Alpha", is_default: true },
  { id: "s2", name: "Beta", is_default: false },
] as unknown as IPSpace[];

describe("FilterModePicker", () => {
  const setup = () => {
    const onChange = vi.fn();
    wrap(
      <div>
        <h1>Heading</h1>
        <FilterModePicker value="begins" onChange={onChange} />
        <HeaderMenu
          label="Tools"
          items={[{ key: "t", label: "Tool", onSelect() {} }]}
        />
      </div>,
    );
    return onChange;
  };

  it("is named for what it does, not for its glyph", () => {
    setup();
    expect(
      screen.getByRole("button", { name: "Filter mode: Begins" }),
    ).toBeTruthy();
  });

  it("closes on one Esc and returns focus to its button", async () => {
    setup();
    const user = userEvent.setup();
    const btn = screen.getByRole("button", { name: /Filter mode/ });
    btn.focus();
    await user.keyboard("{Enter}");
    expect(screen.getByText(/Contains/)).toBeTruthy();
    await user.keyboard("{Escape}");
    expect(screen.queryByText(/Contains/)).toBeNull();
    expect(document.activeElement).toBe(btn);
  });

  it("closes on Esc after a mouse open (focus on body)", () => {
    setup();
    fireEvent.click(screen.getByRole("button", { name: /Filter mode/ }));
    (document.activeElement as HTMLElement | null)?.blur();
    fireEvent.keyDown(document.body, { key: "Escape" });
    expect(screen.queryByText(/Contains/)).toBeNull();
  });

  it("closes on a press elsewhere", () => {
    setup();
    fireEvent.click(screen.getByRole("button", { name: /Filter mode/ }));
    expect(screen.getByText(/Contains/)).toBeTruthy();
    fireEvent.mouseDown(screen.getByText("Heading"));
    expect(screen.queryByText(/Contains/)).toBeNull();
  });

  it("closes when the Tools menu beside it takes focus", async () => {
    setup();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Filter mode/ }));
    expect(screen.getByText(/Contains/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: /Tools/ }));
    expect(screen.queryByText(/Contains/)).toBeNull();
    expect(screen.getByRole("menu")).toBeTruthy();
  });

  it("a pick applies, closes and returns focus", async () => {
    const onChange = setup();
    const user = userEvent.setup();
    const btn = screen.getByRole("button", { name: /Filter mode/ });
    await user.click(btn);
    await user.click(screen.getByText(/Regex/));
    expect(onChange).toHaveBeenCalledWith("regex");
    expect(screen.queryByText(/Regex/)).toBeNull();
    expect(document.activeElement).toBe(btn);
  });
});

describe("SavedViewsMenu", () => {
  it("closes on Esc and on a press elsewhere", async () => {
    wrap(
      <div>
        <h1>Heading</h1>
        <SavedViewsMenu page="sites" currentPayload={{}} onApply={() => {}} />
      </div>,
    );
    const user = userEvent.setup();
    const btn = screen.getByRole("button", { name: /Views/ });
    await user.click(btn);
    expect(screen.getByPlaceholderText(/Save current view/)).toBeTruthy();
    await user.keyboard("{Escape}");
    expect(screen.queryByPlaceholderText(/Save current view/)).toBeNull();
    expect(document.activeElement).toBe(btn);
    await user.click(btn);
    fireEvent.mouseDown(screen.getByText("Heading"));
    expect(screen.queryByPlaceholderText(/Save current view/)).toBeNull();
  });
});

describe("Dashboard Spaces filter", () => {
  it("closes on Esc and returns focus", async () => {
    wrap(<IpamSpaceFilter spaces={spaces} selected={[]} onChange={() => {}} />);
    const user = userEvent.setup();
    const btn = screen.getByRole("button", { name: /Spaces: All/ });
    btn.focus();
    await user.keyboard("{Enter}");
    expect(screen.getByText("Beta")).toBeTruthy();
    await user.keyboard("{Escape}");
    expect(screen.queryByText("Beta")).toBeNull();
    expect(document.activeElement).toBe(btn);
  });
});

describe("Aggregation suggestions popover", () => {
  it("closes on Esc and returns focus", async () => {
    sessionStorage.clear();
    wrap(<AggregationCandidatesBadge blockId="b1" />);
    const user = userEvent.setup();
    const btn = await screen.findByRole("button", {
      name: /aggregation suggestion/,
    });
    btn.focus();
    await user.keyboard("{Enter}");
    expect(screen.getByText("Aggregation candidates")).toBeTruthy();
    await user.keyboard("{Escape}");
    expect(screen.queryByText("Aggregation candidates")).toBeNull();
    expect(document.activeElement).toBe(btn);
  });
});
