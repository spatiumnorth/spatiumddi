/**
 * @vitest-environment jsdom
 *
 * The ASN Delete dialog says what goes with the ASN and what is cleared (#2612).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const ASN = {
  id: "a1",
  number: 4200000001,
  name: "lab",
  description: "",
  kind: "private",
  holder_org: null,
  registry: "private",
  whois_state: "n/a",
  whois_last_checked_at: "2026-10-23T00:00:00Z",
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
                : name === "asnsApi" && method === "list"
                  ? async () => ({ items: [ASN], total: 1 })
                  : name === "authApi" && method === "myPermissions"
                    ? async () => ({ is_superadmin: true, grants: [] })
                    : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { AsnsPage } = await import("./AsnsPage");

afterEach(cleanup);

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/network/asns"]}>
        <AsnsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const flat = (el: Element) => (el.textContent ?? "").replace(/\s+/g, " ");

describe("AsnsPage copy (#2612)", () => {
  it("says peerings and communities are deleted and IPAM rows are cleared", async () => {
    show();
    fireEvent.click(await screen.findByLabelText("Select AS4200000001"));
    fireEvent.click(await screen.findByRole("button", { name: /Delete 1/ }));
    const dialog = await screen.findByText(/ROA rows, BGP peerings/);
    const said = flat(dialog);
    expect(said).not.toMatch(/won.t touch/i);
    expect(said).not.toMatch(/follow-up/i);
    expect(said).toMatch(/peerings/);
    expect(said).toMatch(/communities/);
    expect(said).toMatch(/IP blocks, subnets/);
    expect(said).toMatch(/cleared/);
  });
});
