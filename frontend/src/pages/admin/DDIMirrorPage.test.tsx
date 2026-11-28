/**
 * @vitest-environment jsdom
 *
 * The DDI mirror page (#4729): lists sources, opens the cutover rehearsal for
 * one, and says what a rehearsal is (and is not).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const target = {
  id: "t1",
  name: "legacy-grid",
  description: "",
  enabled: true,
  vendor: "infoblox",
  base_url: "https://gm.example.test",
  api_version: "v2.12",
  verify_tls: true,
  ca_bundle_present: false,
  username: "svc",
  password_present: true,
  network_view: "",
  dns_view: "",
  sync_interval_seconds: 900,
  page_size: 500,
  last_synced_at: "2026-11-27T10:00:00Z",
  last_sync_error: null,
  last_sync_warning: null,
  source_version: "WAPI v2.12",
  object_count: 13,
  last_report: null,
  created_at: "2026-11-27T09:00:00Z",
  modified_at: "2026-11-27T10:00:00Z",
};

const counts = (create: number, exists: number, differs: number) => ({
  total: create + exists + differs,
  create,
  exists,
  differs,
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
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : name === "ddiMirrorApi" && method === "list"
                  ? async () => [target]
                  : name === "ddiMirrorApi" && method === "rehearsal"
                    ? async () => ({
                        target_id: "t1",
                        synced_at: "2026-11-27T10:00:00Z",
                        totals: counts(4, 6, 3),
                        kinds: { network: counts(1, 1, 1) },
                        total_items: 1,
                        items: [
                          {
                            kind: "network",
                            name: "10.2.0.0/24",
                            value: "10.2.0.0/24",
                            view: "default",
                            action: "differs",
                            differences: ["comment differs from the live name"],
                          },
                        ],
                      })
                    : name === "authApi" && method === "myPermissions"
                      ? async () => ({ is_superadmin: true, grants: [] })
                      : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { DDIMirrorPage } = await import("./DDIMirrorPage");

afterEach(cleanup);

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DDIMirrorPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("DDI mirror page", () => {
  it("lists a source with its object count", async () => {
    renderPage();
    expect(await screen.findByText("legacy-grid")).toBeTruthy();
    expect(screen.getByText("13 objects")).toBeTruthy();
    expect(screen.getByText("https://gm.example.test")).toBeTruthy();
  });

  it("opens the rehearsal and shows what an import would do", async () => {
    renderPage();
    await screen.findByText("legacy-grid");
    fireEvent.click(screen.getByLabelText("Open legacy-grid"));
    expect(
      await screen.findByText(/Nothing is changed by looking/),
    ).toBeTruthy();
    expect(
      (await screen.findAllByText("10.2.0.0/24", { selector: "td" })).length,
    ).toBeGreaterThan(0);
    expect(screen.getByText("comment differs from the live name")).toBeTruthy();
  });

  it("says the mirror writes nothing live", async () => {
    renderPage();
    const intro = await screen.findByText(/read-only, continuously refreshed/);
    expect(intro.textContent).toMatch(/Nothing is\s+written to the source/);
  });
});
