/**
 * @vitest-environment jsdom
 *
 * An Esc that ends an IME composition belongs to the input method, so the
 * search palette stays open with its query (#3156).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const mockMeta = vi.hoisted(() => ({
  total: 1,
  total_capped: false as boolean,
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    // The shortcuts overlay reads the caller's grants (#3103).
    authApi: {
      ...actual.authApi,
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    },
    tagsApi: {
      ...actual.tagsApi,
      listKeys: () => Promise.resolve({ keys: ["env", "site"] }),
    },
    searchApi: {
      search: () =>
        Promise.resolve({
          total: mockMeta.total,
          total_capped: mockMeta.total_capped,
          results: [
            {
              type: "subnet",
              id: "s1",
              display: "10.0.0.0/24",
              name: "lab",
            },
          ],
        }),
      types: () =>
        Promise.resolve([
          { type: "subnet", group: "ipam" },
          { type: "dns_zone", group: "dns" },
        ]),
    },
  };
});
vi.mock("@/components/copilot/useAiAvailable", () => ({
  useAiAvailable: () => false,
}));
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true, ready: true }),
}));

const { GlobalSearch } = await import("@/components/GlobalSearch");
const { TagFilterChips } = await import("@/components/TagFilterChips");

afterEach(cleanup);

function setup() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <GlobalSearch />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("palette Esc and IME composition (#3156)", () => {
  async function open() {
    fireEvent.keyDown(document, { key: "k", ctrlKey: true });
    const box = await screen.findByRole("combobox", { name: "Search" });
    await vi.waitFor(() => expect(document.activeElement).toBe(box));
    fireEvent.change(box, { target: { value: "meridian" } });
    return box as HTMLInputElement;
  }

  it("keeps the palette and its query on a composing Esc", async () => {
    setup();
    const box = await open();
    fireEvent.keyDown(box, { key: "Escape", isComposing: true, keyCode: 229 });
    expect(screen.queryByRole("dialog", { name: "Search" })).not.toBeNull();
    expect(box.value).toBe("meridian");
  });

  it("treats keyCode 229 alone as a composing Esc", async () => {
    setup();
    const box = await open();
    fireEvent.keyDown(box, { key: "Escape", keyCode: 229 });
    expect(screen.queryByRole("dialog", { name: "Search" })).not.toBeNull();
  });

  it("still closes on a plain Esc afterwards", async () => {
    setup();
    const box = await open();
    fireEvent.keyDown(box, { key: "Escape", isComposing: true, keyCode: 229 });
    fireEvent.keyDown(box, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Search" })).toBeNull();
  });

  it("leaves the tag filter's draft and list alone on a composing Esc", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <TagFilterChips value={[]} onChange={() => {}} />
      </QueryClientProvider>,
    );
    const box = screen.getByPlaceholderText(
      /Filter by tag/,
    ) as HTMLInputElement;
    fireEvent.focus(box);
    fireEvent.change(box, { target: { value: "en" } });
    await screen.findByText("env");
    fireEvent.keyDown(box, { key: "Escape", isComposing: true, keyCode: 229 });
    expect(box.value).toBe("en");
    expect(screen.queryByText("env")).not.toBeNull();
    fireEvent.keyDown(box, { key: "Escape" });
    expect(box.value).toBe("");
  });
});
