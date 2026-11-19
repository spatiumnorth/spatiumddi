/**
 * @vitest-environment jsdom
 *
 * A refused CT-log lookup is announced (role="alert"), not only drawn red (#4408).
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
                : name === "tlsCertsApi" && method === "ctLog"
                  ? async () => {
                      throw new Error("crt.sh unreachable");
                    }
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

function renderPage() {
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
}

describe("CertificatesPage CT-log refusal (#4408)", () => {
  it("announces a failed CT-log lookup", async () => {
    renderPage();
    fireEvent.click(
      await screen.findByRole("button", {
        name: "View certificate details for example.test:443",
      }),
    );
    fireEvent.click(
      await screen.findByText(/CT-log cross-reference/, undefined, {
        timeout: 10000,
      }),
    );
    const alert = await screen.findByRole("alert", {}, { timeout: 10000 });
    expect(alert.textContent).toMatch(/CT-log lookup failed/);
  }, 30000);
});
