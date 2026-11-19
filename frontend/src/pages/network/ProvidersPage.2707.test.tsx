/**
 * @vitest-environment jsdom
 *
 * A refused provider delete says so in the server's words (#2707).
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
import { MemoryRouter } from "react-router-dom";

const PROVIDER = {
  id: "p1",
  name: "Cogent",
  kind: "transit",
  account_number: null,
  default_asn_id: null,
  contact_email: null,
  contact_phone: null,
  tags: {},
  custom_fields: {},
};
const DETAIL = "Cannot delete provider while circuits reference it.";

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
                : name === "providersApi" && method === "list"
                  ? async () => ({ items: [PROVIDER], total: 1 })
                  : name === "providersApi" && method === "remove"
                    ? async () => {
                        throw Object.assign(new Error("409"), {
                          response: { status: 409, data: { detail: DETAIL } },
                        });
                      }
                    : name === "authApi" && method === "myPermissions"
                      ? async () => ({ is_superadmin: true, grants: [] })
                      : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { ProvidersPage } = await import("./ProvidersPage");

afterEach(cleanup);

describe("ProvidersPage delete refusal (#2707)", () => {
  it("shows the server's 409 after the confirm closes", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <ProvidersPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByTitle("Delete"));
    const deletes = await screen.findAllByRole("button", { name: "Delete" });
    fireEvent.click(deletes[deletes.length - 1]);
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain(DETAIL),
    );
  });
});
