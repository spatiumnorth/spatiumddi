/**
 * @vitest-environment jsdom
 *
 * A refused delete on the Overlays, Customers, PIM domains, Circuits, Services and TLS certificate lists says so
 * in the server's words and re-reads the list (#3822).
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

const DETAIL = "Thing not found";
const listCalls: Record<string, number> = {};

const ROWS: Record<string, Record<string, unknown>> = {
  overlaysApi: {
    id: "o1",
    name: "ov-one",
    kind: "sdwan",
    tags: {},
    custom_fields: {},
  },
  customersApi: { id: "c1", name: "cust-one", tags: {}, custom_fields: {} },
  multicastApi: { id: "d1", name: "dom-one", tags: {}, custom_fields: {} },
  circuitsApi: {
    id: "ci1",
    name: "circ-one",
    tags: {},
    custom_fields: {},
  },
  servicesApi: {
    id: "s1",
    name: "svc-one",
    resources: [],
    tags: {},
    custom_fields: {},
  },
  tlsCertsApi: {
    id: "t1",
    host: "host-one",
    display_name: "tls-one",
    port: 443,
    tags: {},
    custom_fields: {},
  },
};
const LIST_METHOD: Record<string, string> = {
  overlaysApi: "list",
  customersApi: "list",
  multicastApi: "listDomains",
  circuitsApi: "list",
  servicesApi: "list",
  tlsCertsApi: "list",
};
const REMOVE_METHOD: Record<string, string> = {
  overlaysApi: "remove",
  customersApi: "remove",
  multicastApi: "deleteDomain",
  circuitsApi: "remove",
  servicesApi: "remove",
  tlsCertsApi: "remove",
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
              if (name === "authApi" && method === "myPermissions")
                return async () => ({ is_superadmin: true, grants: [] });
              if (name === "featureModulesApi" && method === "list")
                return async () => [
                  {
                    id: "security.tls_certs",
                    label: "x",
                    group: "x",
                    description: "",
                    default_enabled: true,
                    enabled: true,
                    requires: [],
                  },
                ];
              if (ROWS[name] && method === LIST_METHOD[name])
                return async () => {
                  listCalls[name] = (listCalls[name] ?? 0) + 1;
                  const row = ROWS[name];
                  return name === "multicastApi"
                    ? [row]
                    : { items: [row], total: 1 };
                };
              if (ROWS[name] && method === REMOVE_METHOD[name])
                return async () => {
                  throw Object.assign(new Error("404"), {
                    response: { status: 404, data: { detail: DETAIL } },
                  });
                };
              return pending;
            },
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { OverlaysPage } = await import("./OverlaysPage");
const { CustomersPage } = await import("./CustomersPage");
const { MulticastDomainsTab } = await import("./MulticastDomainsPage");
const { CircuitsPage } = await import("./CircuitsPage");
const { ServicesPage } = await import("./ServicesPage");
const { CertificatesPage } = await import("./CertificatesPage");

afterEach(cleanup);

const CASES = [
  ["Overlays", "overlaysApi", OverlaysPage],
  ["Customers", "customersApi", CustomersPage],
  ["PIM domains", "multicastApi", MulticastDomainsTab],
  ["Circuits", "circuitsApi", CircuitsPage],
  ["Services", "servicesApi", ServicesPage],
  ["TLS certificates", "tlsCertsApi", CertificatesPage],
] as const;

describe("a refused list delete (#3822)", () => {
  it.each(CASES)("%s says why and re-reads the list", async (_n, api, Page) => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <Page />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByTitle("Delete"));
    await waitFor(() => expect(listCalls[api]).toBeGreaterThan(0));
    const before = listCalls[api];
    const deletes = await screen.findAllByRole("button", { name: "Delete" });
    fireEvent.click(deletes[deletes.length - 1]);
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain(DETAIL),
    );
    await waitFor(() => expect(listCalls[api]).toBeGreaterThan(before));
  });
});
