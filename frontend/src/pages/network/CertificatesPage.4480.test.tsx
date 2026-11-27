/**
 * @vitest-environment jsdom
 *
 * A crt.sh failure reaches the page as a 200 carrying `error` (#4480), not as
 * a failed request, so the dialog must announce it itself.
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

// Same host:port, told apart only by SNI (the table's dedupe key is
// host + port + server_name), so each row's button needs its own name.
const SNI_A = { ...TARGET, id: "t2", port: 8443, server_name: "a.sni.test" };
const SNI_B = { ...TARGET, id: "t3", port: 8443, server_name: "b.sni.test" };

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
                  ? async () => ({ items: [TARGET, SNI_A, SNI_B], total: 3 })
                  : name === "tlsCertsApi" && method === "ctLog"
                    ? async () => ({
                        entries: [],
                        error:
                          "CT-log lookup failed (crt.sh unreachable or rate-limited)",
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

describe("CertificatesPage CT-log failure (#4480)", () => {
  it("announces a crt.sh failure the API reports in a 200", async () => {
    renderPage();
    fireEvent.click(
      await screen.findByRole("button", {
        name: "View certificate details for example.test:443",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: /Show CT-log cross-reference/,
      }),
    );
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain(
      "CT-log lookup failed (crt.sh unreachable",
    );
  });
});
