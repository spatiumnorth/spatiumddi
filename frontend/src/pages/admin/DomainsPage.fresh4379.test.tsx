/**
 * @vitest-environment jsdom
 *
 * The Domains Edit dialog reads the domain when it opens and a Save sends only
 * what the operator changed (#4379). Before, it seeded from the list row and
 * sent every field, putting back what another client stored since.
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

const h = vi.hoisted(() => ({ update: vi.fn() }));

const base = {
  id: "d1",
  name: "example.com",
  registrar: null,
  registrant_org: null,
  registered_at: null,
  expires_at: null,
  last_renewed_at: null,
  expected_nameservers: ["old.example.com"],
  actual_nameservers: [],
  nameserver_drift: false,
  dnssec_signed: false,
  whois_last_checked_at: "2026-10-01T00:00:00Z",
  whois_state: "ok",
  whois_data: null,
  next_check_at: null,
  tags: {},
  custom_fields: {},
  customer_id: null,
  registrar_provider_id: null,
  created_at: "2026-10-01T00:00:00Z",
  modified_at: "2026-10-01T00:00:00Z",
};
// What another client stored after the list loaded.
const fresh = {
  ...base,
  expected_nameservers: ["fresh.example.com"],
  customer_id: "c2",
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    },
    domainsApi: {
      ...actual.domainsApi,
      list: async () => ({ items: [base], total: 1, page: 1, page_size: 200 }),
      get: async () => fresh,
      update: (...a: unknown[]) => {
        h.update(...a);
        return Promise.resolve(fresh);
      },
    },
  };
});
vi.mock("@/hooks/useOwnershipModules", () => ({
  useOwnershipModules: () => ({
    customer: false,
    site: false,
    provider: false,
  }),
}));

const { DomainsPage } = await import("./DomainsPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

async function openEdit() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>
        <DomainsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const edit = await screen.findByTitle(/edit/i, {}, { timeout: 10000 });
  fireEvent.click(edit);
  return screen.findByPlaceholderText(
    /ns1\.example\.com/,
    {},
    { timeout: 10000 },
  );
}

describe(
  "Domains Edit reads the row and saves only the change",
  { timeout: 30000 },
  () => {
    it("shows the values stored since the list loaded", async () => {
      const ns = (await openEdit()) as HTMLTextAreaElement;
      expect(ns.value).toBe("fresh.example.com");
    });

    it("an unrelated Save sends only that field", async () => {
      await openEdit();
      const name = screen.getByPlaceholderText("example.com");
      fireEvent.change(name, { target: { value: "example.org" } });
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(() => expect(h.update).toHaveBeenCalled(), {
        timeout: 10000,
      });
      expect(h.update).toHaveBeenCalledWith("d1", { name: "example.org" });
    });

    it("an untouched Save sends nothing", async () => {
      await openEdit();
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(
        () => expect(screen.queryByRole("button", { name: "Save" })).toBeNull(),
        { timeout: 10000 },
      );
      expect(h.update).not.toHaveBeenCalled();
    });
  },
);
