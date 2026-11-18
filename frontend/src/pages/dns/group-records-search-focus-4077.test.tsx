/**
 * @vitest-environment jsdom
 *
 * DNS group Records search keeps focus while typing (#4077): the term was in
 * the query key, each keystroke started a data-less query, and the early
 * "Loading records…" return unmounted the input.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { DNSServerGroup } from "@/lib/api";

const listGroupRecords = vi.fn();
const empty = () => Promise.resolve([]);

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      listGroupRecords: (...a: unknown[]) => listGroupRecords(...a),
      listZones: empty,
      listViews: empty,
    },
  };
});

const { RecordsTab } = await import("./DNSPage");

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  listGroupRecords.mockReset();
});

describe("group records search (#4077)", () => {
  it("keeps focus and value while typing, and queries once after the debounce", async () => {
    listGroupRecords.mockImplementation(
      () =>
        new Promise((res) =>
          setTimeout(() => res({ items: [], total: 0, page: 1 }), 20),
        ),
    );
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <RecordsTab
            group={{ id: "g1", name: "edge" } as DNSServerGroup}
            onSelectZone={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const box = (await screen.findByPlaceholderText(
      /Search name/,
    )) as HTMLInputElement;
    box.focus();
    for (const v of ["w", "ww", "www"]) {
      fireEvent.change(box, { target: { value: v } });
      await act(async () => {
        await new Promise((r) => setTimeout(r, 30));
      });
      expect(screen.getByPlaceholderText(/Search name/)).toBe(box);
      expect(document.activeElement).toBe(box);
      expect(box.value).toBe(v);
    }
    await act(async () => {
      await new Promise((r) => setTimeout(r, 450));
    });
    expect(document.activeElement).toBe(box);
    expect(box.value).toBe("www");
    const searches = listGroupRecords.mock.calls.map(
      (c) => (c[1] as { search?: string }).search,
    );
    expect(searches).toEqual([undefined, "www"]);
  });
});
