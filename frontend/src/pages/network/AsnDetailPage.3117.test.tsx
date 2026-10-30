/**
 * @vitest-environment jsdom
 *
 * A private ASN's page does not tell the operator to run the Refresh WHOIS it disables (#3117).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";

const ASN = {
  id: "a1",
  number: 4200009101,
  name: "lab",
  description: "",
  kind: "private",
  holder_org: null,
  registry: "private",
  whois_state: "n/a",
  whois_last_checked_at: "2026-10-23T00:00:00Z",
  whois_data: null,
  tags: {},
  custom_fields: {},
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
                  : name === "asnsApi" && method === "get"
                    ? async () => current
                    : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { AsnDetailPage } = await import("./AsnDetailPage");

let current: Record<string, unknown> = ASN;

afterEach(() => {
  cleanup();
  current = ASN;
});

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/network/asns/a1"]}>
        <Routes>
          <Route path="/network/asns/:id" element={<AsnDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AsnDetailPage WHOIS empty state (#3117)", () => {
  it("says a private ASN has no public WHOIS instead of 'run Refresh WHOIS'", async () => {
    show();
    const msg = await screen.findByText(/No raw WHOIS data/);
    expect(msg.textContent).toMatch(/no public WHOIS/i);
    expect(msg.textContent).not.toMatch(/run Refresh WHOIS/i);
  });

  it("still points a public ASN at the Refresh WHOIS it can press", async () => {
    current = {
      ...ASN,
      number: 13335,
      kind: "public",
      registry: "arin",
      whois_state: "unknown",
    };
    show();
    const msg = await screen.findByText(/No raw WHOIS data/);
    expect(msg.textContent).toMatch(/run Refresh WHOIS/i);
    const button = screen.getByRole("button", { name: /Refresh WHOIS/ });
    expect((button as HTMLButtonElement).disabled).toBe(false);
  });
});
