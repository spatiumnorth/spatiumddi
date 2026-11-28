/**
 * @vitest-environment jsdom
 *
 * The Emergency Response Location Edit dialog reads the location when it
 * opens and a Save sends only what the operator changed (#4379). Before, it
 * seeded from the click-time list row and sent every field, so a value another client stored
 * since the list loaded was put back by an unrelated Save.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const h = vi.hoisted(() => ({ update: vi.fn() }));

const BASE = {
  id: "e1",
  name: "HQ Lobby",
  site_id: null,
  elins: [],
  validation_state: "unvalidated",
  validated_at: null,
  validation_source: null,
  validation_detail: null,
  is_dispatchable: false,
  is_active: true,
  notes: "",
  binding_count: 0,
  latitude: null,
  longitude: null,
  created_at: "",
  modified_at: "",
};
const FRESH = { ...BASE, name: "HQ Lobby (renamed elsewhere)", a3: "Ottawa" };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    e911Api: {
      ...actual.e911Api,
      // The list holds the stale row; the dialog reads the row itself.
      listErls: () =>
        Promise.resolve({ items: [BASE], total: 1, limit: 50, offset: 0 }),
      getErl: () => Promise.resolve(FRESH),
      listBindings: () =>
        Promise.resolve({ items: [], total: 0, limit: 50, offset: 0 }),
      updateErl: (...a: unknown[]) => {
        h.update(...a);
        return Promise.resolve(FRESH);
      },
    },
    sitesApi: {
      ...actual.sitesApi,
      list: () =>
        Promise.resolve({ items: [], total: 0, limit: 500, offset: 0 }),
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
      canExplicit: () => false,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

const { E911Page } = await import("./E911Page");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

async function openEdit() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <E911Page />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(await screen.findByTitle("Edit", {}, { timeout: 10000 }));
  return (await screen.findByDisplayValue(
    "HQ Lobby (renamed elsewhere)",
    {},
    { timeout: 10000 },
  )) as HTMLInputElement;
}

describe("E911 location Edit dialog (#4379)", { timeout: 30000 }, () => {
  it("shows what is stored now, not the click-time list row", async () => {
    const name = await openEdit();
    expect(name.value).toBe("HQ Lobby (renamed elsewhere)");
    expect(screen.getByDisplayValue("Ottawa")).toBeTruthy();
  });

  it("an unrelated change sends only that field", async () => {
    const name = await openEdit();
    fireEvent.change(name, { target: { value: "HQ Lobby 2" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(h.update).toHaveBeenCalledTimes(1), {
      timeout: 10000,
    });
    expect(h.update).toHaveBeenCalledWith("e1", { name: "HQ Lobby 2" });
  });

  it("a Save with nothing changed sends nothing", async () => {
    await openEdit();
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(
      () =>
        expect(
          screen.queryByDisplayValue("HQ Lobby (renamed elsewhere)"),
        ).toBeNull(),
      { timeout: 10000 },
    );
    expect(h.update).not.toHaveBeenCalled();
  });
});
