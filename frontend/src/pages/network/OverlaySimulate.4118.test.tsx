/**
 * @vitest-environment jsdom
 *
 * An overlay's Simulate tab never writes, but the route is write-scoped on
 * 'overlay_network'. A read-only user sees "Run simulation" disabled with the
 * permission it needs, and a refused run says why instead of "Simulation
 * failed" (#4118). Real `usePermissions`.
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
import { MemoryRouter, Route, Routes } from "react-router-dom";

let grants: [string, string][] = [];

const OVERLAY = {
  id: "o1",
  name: "Branch mesh",
  kind: "sdwan",
  customer_id: null,
  vendor: null,
  encryption_profile: null,
  default_path_strategy: "active_backup",
  status: "building",
  notes: "",
  site_count: 0,
  policy_count: 0,
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
            get: (_t, method) => {
              if (typeof method === "symbol") return undefined;
              if (name === "overlaysApi" && method === "get")
                return async () => OVERLAY;
              if (name === "overlaysApi" && method === "listSites")
                return async () => [];
              if (name === "circuitsApi" && method === "list")
                return async () => ({ items: [], total: 0 });
              if (name === "overlaysApi" && method === "simulate")
                return async () => {
                  throw Object.assign(new Error("403"), {
                    response: {
                      status: 403,
                      data: {
                        detail:
                          "Permission denied: need 'write' on 'overlay_network'",
                      },
                    },
                  });
                };
              if (name === "authApi" && method === "myPermissions")
                return async () => ({
                  is_superadmin: false,
                  grants: grants.map(([action, resource_type]) => ({
                    action,
                    resource_type,
                    resource_id: null,
                  })),
                });
              return pending;
            },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { OverlayDetailPage } = await import("./OverlayDetailPage");

afterEach(cleanup);

async function openSimulate(g: [string, string][]) {
  grants = g;
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/network/overlays/o1"]}>
        <Routes>
          <Route path="/network/overlays/:id" element={<OverlayDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(await screen.findByRole("button", { name: /Simulate/ }));
  return (await screen.findByRole("button", {
    name: /Run simulation/,
  })) as HTMLButtonElement;
}

describe("Overlay Simulate tab (#4118)", () => {
  it("disables Run simulation, with the permission, for a read-only user", async () => {
    const btn = await openSimulate([["read", "overlay_network"]]);
    await waitFor(() => expect(btn.disabled).toBe(true));
    expect(btn.title).toMatch(/write permission on overlay networks/);
  });

  it("enables it for a user who can write overlays", async () => {
    const btn = await openSimulate([
      ["read", "overlay_network"],
      ["write", "overlay_network"],
    ]);
    await waitFor(() => expect(btn.disabled).toBe(false));
  });

  it("says why a refused run was refused", async () => {
    const btn = await openSimulate([
      ["read", "overlay_network"],
      ["write", "overlay_network"],
    ]);
    await waitFor(() => expect(btn.disabled).toBe(false));
    fireEvent.click(btn);
    expect(
      await screen.findByText(/need 'write' on 'overlay_network'/),
    ).toBeTruthy();
  });
});
