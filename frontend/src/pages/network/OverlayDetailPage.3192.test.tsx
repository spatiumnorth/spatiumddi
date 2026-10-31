/**
 * @vitest-environment jsdom
 *
 * An overlay whose customer is in the Trash says so, instead of showing the
 * Customer card as "Loading…" for ever (#3192).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";

const OVERLAY = {
  id: "o1",
  name: "Branch mesh",
  kind: "sdwan",
  customer_id: "c-gone",
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
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : name === "overlaysApi" && method === "get"
                  ? async () => OVERLAY
                  : name === "customersApi" && method === "get"
                    ? async () => {
                        throw Object.assign(new Error("404"), {
                          response: { status: 404 },
                        });
                      }
                    : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { OverlayDetailPage } = await import("./OverlayDetailPage");

afterEach(cleanup);

describe("OverlayDetailPage customer card (#3192)", () => {
  it("says the customer is in the Trash when it cannot be fetched", async () => {
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/network/overlays/o1"]}>
          <Routes>
            <Route
              path="/network/overlays/:id"
              element={<OverlayDetailPage />}
            />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await waitFor(() =>
      expect(screen.getByText("(customer in Trash)")).toBeTruthy(),
    );
    expect(screen.queryByText("Loading…")).toBeNull();
  });
});
