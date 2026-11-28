/**
 * @vitest-environment jsdom
 *
 * A multicast domain's Edit dialog reads the row when it opens and a Save sends only what
 * the operator changed (#4379). The list holds the click-time row; the single
 * read answers with what another client stored since.
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

const STALE: Record<string, unknown> = {
  id: "r1",
  name: "dom",
  description: "old value",
  pim_mode: "sparse",
  rendezvous_point_address: "192.0.2.1",
  ssm_range: null,
  notes: "",
};
const FRESH: Record<string, unknown> = {
  ...STALE,
  description: "changed elsewhere",
};

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
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : name === "authApi" && method === "myPermissions"
                  ? async () => ({ is_superadmin: true, grants: [] })
                  : name === "multicastApi" && method === "listDomains"
                    ? async () => [STALE]
                    : name === "multicastApi" && method === "getDomain"
                      ? async () => FRESH
                      : name === "multicastApi" && method === "updateDomain"
                        ? async (...a: unknown[]) => {
                            h.update(...a);
                            return FRESH;
                          }
                        : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { MulticastDomainsTab } = await import("./MulticastDomainsPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function open() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <MulticastDomainsTab />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("A multicast domain's Edit dialog (#4379)", { timeout: 30000 }, () => {
  it("opens on what is stored now", async () => {
    open();
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit" }, { timeout: 10000 }),
    );
    await screen.findByDisplayValue(
      "changed elsewhere",
      {},
      { timeout: 10000 },
    );
    expect(screen.queryByDisplayValue("old value")).toBeNull();
  });

  it("an unrelated change sends only that field", async () => {
    open();
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit" }, { timeout: 10000 }),
    );
    fireEvent.change(
      await screen.findByDisplayValue("dom", {}, { timeout: 10000 }),
      { target: { value: "renamed" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(h.update).toHaveBeenCalledTimes(1), {
      timeout: 10000,
    });
    expect(h.update).toHaveBeenCalledWith("r1", { name: "renamed" });
  });

  it("an untouched Save sends nothing", async () => {
    open();
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit" }, { timeout: 10000 }),
    );
    await screen.findByDisplayValue(
      "changed elsewhere",
      {},
      { timeout: 10000 },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(
      () => expect(screen.queryByRole("button", { name: "Save" })).toBeNull(),
      {
        timeout: 10000,
      },
    );
    expect(h.update).not.toHaveBeenCalled();
  });
});
