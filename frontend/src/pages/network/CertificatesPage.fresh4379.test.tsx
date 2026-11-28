/**
 * @vitest-environment jsdom
 *
 * A certificate target's Edit dialog reads the row when it opens and a Save sends only what
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
  host: "example.test",
  port: 443,
  server_name: null,
  display_name: "old value",
  interval_hours: null,
  enabled: true,
  source: "manual",
  state: "unknown",
};
const FRESH: Record<string, unknown> = {
  ...STALE,
  display_name: "changed elsewhere",
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
                  : name === "tlsCertsApi" && method === "list"
                    ? async () => ({ items: [STALE], total: 1 })
                    : name === "tlsCertsApi" && method === "get"
                      ? async () => FRESH
                      : name === "tlsCertsApi" && method === "update"
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

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true, ready: true }),
}));

const { CertificatesPage } = await import("./CertificatesPage");

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
        <CertificatesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe(
  "A certificate target's Edit dialog (#4379)",
  { timeout: 30000 },
  () => {
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
        await screen.findByDisplayValue("example.test", {}, { timeout: 10000 }),
        { target: { value: "renamed" } },
      );
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(() => expect(h.update).toHaveBeenCalledTimes(1), {
        timeout: 10000,
      });
      expect(h.update).toHaveBeenCalledWith("r1", { host: "renamed" });
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
  },
);
