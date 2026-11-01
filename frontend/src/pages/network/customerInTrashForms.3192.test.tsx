/**
 * @vitest-environment jsdom
 *
 * The Services and Overlays edit forms keep a customer that is in the Trash
 * selected and say so, rather than falling back to their placeholder (#3192).
 * Only a loaded, complete customer list can say the customer is in the Trash.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

const LIVE = { id: "c-live", name: "Live Co" };

// How GET /customers answers in each case; set by the test.
let listMode: "complete" | "truncated" | "error" = "complete";

const SERVICE = {
  id: "s1",
  name: "Branch WAN",
  kind: "custom",
  customer_id: "c-gone",
  status: "active",
  sla_tier: null,
  term_start_date: null,
  term_end_date: null,
  monthly_cost_usd: null,
  currency: "USD",
  notes: "",
  tags: {},
  custom_fields: {},
  resources: [],
};

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
  const customersList = async () => {
    if (listMode === "error")
      throw Object.assign(new Error("500"), { response: { status: 500 } });
    return {
      items: [LIVE],
      total: listMode === "truncated" ? 600 : 1,
      limit: 500,
      offset: 0,
    };
  };
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
                  ? customersList
                  : name === "servicesApi" && method === "get"
                    ? async () => SERVICE
                    : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { ServiceEditorModal } = await import("./ServicesPage");
const { OverlayEditorModal } = await import("./OverlaysPage");

afterEach(cleanup);

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function customerSelect(): HTMLSelectElement {
  const live = screen.getByRole("option", { name: LIVE.name });
  return live.closest("select") as HTMLSelectElement;
}

const forms: [string, () => ReactNode][] = [
  [
    "service",
    () => (
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      <ServiceEditorModal existing={SERVICE as any} onClose={() => {}} />
    ),
  ],
  [
    "overlay",
    () => (
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      <OverlayEditorModal existing={OVERLAY as any} onClose={() => {}} />
    ),
  ],
];

describe.each(forms)("%s edit form customer (#3192)", (_kind, ui) => {
  it("keeps a customer in the Trash selected and says so", async () => {
    listMode = "complete";
    wrap(ui());
    await waitFor(() =>
      expect(
        screen.getByRole("option", { name: "(customer in Trash)" }),
      ).toBeTruthy(),
    );
    expect(customerSelect().value).toBe("c-gone");
  });

  it("does not say Trash when the list may be on another page", async () => {
    listMode = "truncated";
    wrap(ui());
    await waitFor(() =>
      expect(
        screen.getByRole("option", { name: "(current customer)" }),
      ).toBeTruthy(),
    );
    expect(screen.queryByText("(customer in Trash)")).toBeNull();
    expect(customerSelect().value).toBe("c-gone");
  });

  it("does not say Trash when the customer list failed to load", async () => {
    listMode = "error";
    wrap(ui());
    // Give the failed list time to settle before asserting the absence.
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByText("(customer in Trash)")).toBeNull();
    expect(screen.queryByText("(current customer)")).toBeNull();
  });
});
