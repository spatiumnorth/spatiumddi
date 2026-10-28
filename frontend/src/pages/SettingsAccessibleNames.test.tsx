/**
 * @vitest-environment jsdom
 *
 * #2952: every text box, number box, select and switch in every Settings
 * section must have an accessible name. A row's visible label is a plain
 * element beside its control, so `Field` is what ties the two together.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ is_superadmin: true }) },
    settingsApi: {
      ...actual.settingsApi,
      get: async () => ({ app_title: "SpatiumDDI" }),
      getDefaults: async () => ({}),
    },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true, ready: true }),
}));

const { SettingsPage } = await import("./SettingsPage");

afterEach(cleanup);

const CONTROLS =
  'input:not([type="hidden"]):not([type="file"]), select, textarea, [role="switch"]';

function nameOf(el: Element): string {
  const ids = el.getAttribute("aria-labelledby");
  if (ids) {
    return ids
      .split(/\s+/)
      .map((id) => document.getElementById(id)?.textContent ?? "")
      .join(" ")
      .trim();
  }
  const aria = el.getAttribute("aria-label");
  if (aria) return aria.trim();
  const labels = (el as HTMLInputElement).labels;
  if (labels && labels.length) return (labels[0].textContent ?? "").trim();
  return "";
}

describe("Settings controls have accessible names (#2952)", () => {
  it("names every control in every section", async () => {
    const { container } = render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <SettingsPage />
      </QueryClientProvider>,
    );
    await screen.findByDisplayValue("SpatiumDDI");
    const nav = container.querySelector("nav") as HTMLElement;
    const titles = within(nav)
      .getAllByRole("button")
      .map((b) => b.textContent ?? "");
    expect(titles.length).toBeGreaterThan(10);

    const unnamed: string[] = [];
    let checked = 0;
    for (const title of titles) {
      fireEvent.click(within(nav).getByRole("button", { name: title }));
      const main = container.querySelector("main") as HTMLElement;
      await waitFor(() =>
        expect(main.querySelector("h2")?.textContent).toBe(title),
      );
      // Let each pane's own queries settle so late-rendered rows count.
      await new Promise((r) => setTimeout(r, 0));
      main.querySelectorAll(CONTROLS).forEach((el) => {
        checked++;
        if (!nameOf(el)) {
          unnamed.push(
            `${title}: <${el.tagName.toLowerCase()} ${el.getAttribute("type") ?? el.getAttribute("role") ?? ""}>`,
          );
        }
      });
    }
    expect(checked).toBeGreaterThan(30);
    expect(unnamed).toEqual([]);
  }, 120_000);
});
