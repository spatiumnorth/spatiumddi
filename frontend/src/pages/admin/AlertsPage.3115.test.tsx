/**
 * @vitest-environment jsdom
 *
 * The Alerts header names the delivery channels the New rule dialog offers (#3115).
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
                  : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { AlertsPage } = await import("./AlertsPage");

afterEach(cleanup);

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/admin/alerts"]}>
        <Routes>
          <Route path="/admin/alerts" element={<AlertsPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AlertsPage header (#3115)", () => {
  it("names email alongside syslog and webhook", () => {
    show();
    const header = screen.getByRole("heading", { name: "Alerts" })
      .parentElement as HTMLElement;
    const text = header.textContent ?? "";
    expect(text).toMatch(/syslog/i);
    expect(text).toMatch(/webhook/i);
    expect(text).toMatch(/email|smtp/i);
  });
});

describe("Delivery channels copy (#4779)", () => {
  it("names the target filters instead of promising every target", async () => {
    show();
    // The button is gated until the permissions query resolves.
    await waitFor(() => {
      fireEvent.click(screen.getByText("New rule"));
      expect(screen.getByText("Delivery channels")).toBeTruthy();
    });
    const box = screen.getByText("Delivery channels")
      .parentElement as HTMLElement;
    const text = (box.textContent ?? "").replace(/\s+/g, " ");
    expect(text).toMatch(/minimum severity and resource type filters accept/);
  });
});
