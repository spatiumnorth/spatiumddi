/**
 * @vitest-environment jsdom
 *
 * A target's detail opens from the keyboard (#3488): the row carries a real
 * button, so Tab reaches it and Enter / Space (a button's native click) open it.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const TARGET = {
  id: "t1",
  host: "example.test",
  port: 443,
  display_name: null,
  state: "ok",
  issuer_cn: "Test CA",
  not_after: "2027-01-01T00:00:00Z",
  days_remaining: 60,
  source: "manual",
  last_checked_at: "2026-11-01T00:00:00Z",
  serial_number: "SERIAL-3488",
  sans_json: ["a.example.test"],
  tags: {},
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
                : name === "tlsCertsApi" && method === "list"
                  ? async () => ({ items: [TARGET], total: 1 })
                  : name === "authApi" && method === "myPermissions"
                    ? async () => ({ is_superadmin: true, grants: [] })
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

afterEach(cleanup);

describe("CertificatesPage keyboard access (#3488)", () => {
  it("opens the detail from a focusable button, not only a row click", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/network/certificates"]}>
          <CertificatesPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const btn = await screen.findByRole("button", {
      name: /View certificate details for example\.test:443/,
    });
    btn.focus();
    expect(document.activeElement).toBe(btn);
    // A button's Enter / Space keypress dispatches a click; jsdom does not
    // synthesise it, so assert the element is a native button and click it.
    expect(btn.tagName).toBe("BUTTON");
    expect(btn.getAttribute("type")).toBe("button");
    fireEvent.click(btn);
    expect(await screen.findByText(/Subject alternative names/)).toBeTruthy();
  });
});
