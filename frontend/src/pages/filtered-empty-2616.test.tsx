/**
 * @vitest-environment jsdom
 *
 * A search that matches nothing on a list that holds rows says the filter
 * matched nothing, not "No X yet" (#2616).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

const row = {
  id: "c1",
  name: "Acme",
  status: "active",
  tags: {},
  custom_fields: {},
};

const lists = {
  customers: vi.fn(),
  templates: vi.fn(),
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    customersApi: {
      ...actual.customersApi,
      list: (p: unknown) => lists.customers(p),
    },
    ipamApi: {
      ...actual.ipamApi,
      listTemplates: () => lists.templates(),
    },
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { CustomersPage } = await import("@/pages/network/CustomersPage");
const { IPAMTemplatesPage } = await import("@/pages/admin/IPAMTemplatesPage");

function show(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  for (const fn of Object.values(lists)) fn.mockReset();
});

describe("a search that matches nothing", () => {
  it("Customers: server-side search with no hits", async () => {
    lists.customers.mockImplementation((p: { search?: string }) =>
      Promise.resolve(
        p.search ? { items: [], total: 0 } : { items: [row], total: 1 },
      ),
    );
    show(<CustomersPage />);
    await screen.findByText("Acme");
    fireEvent.change(screen.getByPlaceholderText(/Search name/), {
      target: { value: "zzz" },
    });
    await screen.findByText(/No customers match the current search or filter/);
    expect(screen.queryByText(/No customers yet/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    await screen.findByText("Acme");
  });

  it("Customers: a really empty list still says yet", async () => {
    lists.customers.mockResolvedValue({ items: [], total: 0 });
    show(<CustomersPage />);
    await screen.findByText(/No customers yet/);
  });

  it("IPAM Templates: client-side search with no hits", async () => {
    lists.templates.mockResolvedValue([
      {
        id: "t1",
        name: "dev-app",
        description: "",
        applies_to: "subnet",
        child_layout: null,
        dns_group_id: null,
        dhcp_group_id: null,
        tags: {},
        custom_fields: {},
      },
    ]);
    show(<IPAMTemplatesPage />);
    await screen.findByText("dev-app");
    fireEvent.change(screen.getByPlaceholderText(/Filter by name/), {
      target: { value: "zzz" },
    });
    await screen.findByText(/No templates match the current search or filter/);
    expect(screen.queryByText(/No templates yet/)).toBeNull();
  });
});
