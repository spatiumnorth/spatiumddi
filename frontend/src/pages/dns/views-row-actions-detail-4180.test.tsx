/**
 * @vitest-environment jsdom
 *
 * #4180: Views row actions were hover-only, and a view's details could only be
 * read in the edit form. They are always visible, and a row opens a detail modal.
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
import type { DNSServerGroup } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
let allowed = true;

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      isSuperadmin: false,
      can: () => allowed,
    }),
  };
});

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get:
              (_t, method: string) =>
              (...args: unknown[]) =>
                (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { ViewsTab } = await import("@/pages/dns/DNSPage");

afterEach(() => {
  cleanup();
  allowed = true;
  for (const name of Object.keys(answers)) delete answers[name];
});

const view = {
  id: "v-1",
  group_id: "g-1",
  name: "guest",
  description: "",
  order: 10,
  recursion: false,
  match_clients: ["guest-nets", "10.9.0.0/24"],
  match_destinations: ["any"],
  allow_query: null,
  allow_query_cache: null,
};

function open() {
  answers.dnsApi = {
    listViews: () => Promise.resolve([view]),
    listServers: () => Promise.resolve([]),
    listZones: () =>
      Promise.resolve([
        { id: "z1", name: "guest.example.", view_id: "v-1" },
        { id: "z2", name: "other.example.", view_id: "v-2" },
      ]),
  };
  answers.dnsBlocklistApi = { list: () => Promise.resolve([]) };
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ViewsTab group={{ id: "g-1" } as DNSServerGroup} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Views row actions and detail (#4180)", () => {
  it("row actions are not hover-only", async () => {
    open();
    const edit = await screen.findByRole("button", { name: "Edit view" });
    const del = screen.getByRole("button", { name: "Delete view" });
    for (const b of [edit, del]) {
      for (let el: HTMLElement | null = b; el; el = el.parentElement) {
        expect(el.className).not.toMatch(/opacity-0|group-hover/);
      }
    }
  });

  it("clicking a row opens the detail modal with fields and zones", async () => {
    open();
    fireEvent.click(
      await screen.findByRole("button", { name: /View details of guest/ }),
    );
    const dlg = await screen.findByText(/Zones \(1\)/);
    expect(dlg).toBeTruthy();
    expect(screen.getByText("guest.example.")).toBeTruthy();
    expect(screen.queryByText("other.example.")).toBeNull();
    expect(screen.getAllByText("guest-nets").length).toBeGreaterThan(1);
    expect(screen.getByText("Disabled")).toBeTruthy();
  });

  it("Enter on a focused row opens it", async () => {
    open();
    const row = await screen.findByRole("button", {
      name: /View details of guest/,
    });
    fireEvent.keyDown(row, { key: "Enter" });
    expect(await screen.findByText(/Zones \(1\)/)).toBeTruthy();
  });

  it("Edit from the modal opens the edit form", async () => {
    open();
    fireEvent.click(
      await screen.findByRole("button", { name: /View details of guest/ }),
    );
    await screen.findByText(/Zones \(1\)/);
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    await waitFor(() => expect(screen.getByText("Edit View")).toBeTruthy());
  });

  it("without permission both modal buttons are disabled", async () => {
    allowed = false;
    open();
    fireEvent.click(
      await screen.findByRole("button", { name: /View details of guest/ }),
    );
    await screen.findByText(/Zones \(1\)/);
    const edit = screen.getByRole("button", {
      name: "Edit",
    }) as HTMLButtonElement;
    const del = screen.getByRole("button", {
      name: "Delete",
    }) as HTMLButtonElement;
    expect(edit.disabled).toBe(true);
    expect(del.disabled).toBe(true);
    expect(edit.title).toMatch(/Requires write/);
    expect(del.title).toMatch(/Requires delete/);
  });
});
