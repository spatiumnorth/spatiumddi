/**
 * @vitest-environment jsdom
 *
 * Deleting a customer says what it does (#2613): the handler stamps
 * deleted_at and nothing else, so the dialogs must not promise that
 * cross-references "will be cleared".
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const CUSTOMER = {
  id: "c1",
  name: "acme",
  account_number: null,
  status: "active",
  contact_email: null,
  contact_phone: null,
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
                : name === "customersApi" && method === "list"
                  ? async () => ({ items: [CUSTOMER], total: 1 })
                  : name === "authApi" && method === "myPermissions"
                    ? async () => ({ is_superadmin: true, grants: [] })
                    : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { CustomersPage } = await import("./CustomersPage");

afterEach(cleanup);

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <CustomersPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const flat = (el: Element) => (el.textContent ?? "").replace(/\s+/g, " ");

function check(said: string) {
  expect(said).not.toMatch(/will be cleared/i);
  expect(said).toMatch(/not changed/);
  expect(said).toMatch(/keeps? pointing/);
}

describe("CustomersPage delete copy", () => {
  it("row delete does not promise to clear references", async () => {
    show();
    const del = await screen.findByTitle("Delete");
    fireEvent.click(del);
    check(flat(await screen.findByText(/Soft-delete customer "acme"/)));
  });

  it("bulk delete does not promise to clear references", async () => {
    show();
    await screen.findByText("acme");
    fireEvent.click(screen.getAllByRole("checkbox")[1]);
    fireEvent.click(
      await screen.findByRole("button", { name: /Delete selected/ }),
    );
    check(flat(await screen.findByText(/Soft-delete 1 customer/)));
  });
});
