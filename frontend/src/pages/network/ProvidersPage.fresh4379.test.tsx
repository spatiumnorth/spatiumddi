/**
 * @vitest-environment jsdom
 *
 * The Provider Edit dialog re-reads the row when it opens and sends only
 * what the operator changed (#4379), the FreshEdit pattern #4370 landed
 * for the integration dialogs. Before, it seeded once from the
 * click-time list row and sent every editable field back, putting back
 * what another client stored since the list loaded.
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

const h = vi.hoisted(() => ({
  reads: 0,
  rows: [] as Record<string, unknown>[],
  update: vi.fn(),
}));

function list() {
  const i = Math.min(h.reads, h.rows.length - 1);
  h.reads += 1;
  return Promise.resolve({ items: [h.rows[i]], total: 1 });
}
const update = (...a: unknown[]) => {
  h.update(...a);
  return Promise.resolve(h.rows[h.rows.length - 1]);
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    },
    asnsApi: { ...actual.asnsApi, list: async () => ({ items: [], total: 0 }) },
    providersApi: { ...actual.providersApi, list, update },
  };
});

const { ProvidersPage } = await import("./ProvidersPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  h.reads = 0;
});

const BASE = {
  id: "pr1",
  name: "Cogent",
  kind: "transit",
  account_number: "ACC-1",
  default_asn_id: null,
  contact_email: "old@example.com",
  contact_phone: null,
  notes: "",
  tags: {},
  custom_fields: {},
};

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ProvidersPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe(
  "Provider Edit dialog re-reads the row (#4379)",
  { timeout: 30000 },
  () => {
    it("shows the fresh values, not the click-time row", async () => {
      h.rows = [
        BASE,
        { ...BASE, account_number: "ACC-2", contact_email: "new@example.com" },
      ];
      renderPage();
      await screen.findByText("Cogent", {}, { timeout: 10000 });
      fireEvent.click(screen.getByTitle("Edit"));
      const acct = await screen.findByDisplayValue(
        "ACC-2",
        {},
        { timeout: 10000 },
      );
      expect(acct).toBeTruthy();
      expect(screen.getByDisplayValue("new@example.com")).toBeTruthy();
    });

    it("an unrelated Save sends only the changed field", async () => {
      h.rows = [
        BASE,
        { ...BASE, account_number: "ACC-2", contact_email: "new@example.com" },
      ];
      renderPage();
      await screen.findByText("Cogent", {}, { timeout: 10000 });
      fireEvent.click(screen.getByTitle("Edit"));
      const label = await screen.findByText(
        "Contact phone",
        {},
        { timeout: 10000 },
      );
      const phone = label.parentElement!.querySelector(
        "input",
      ) as HTMLInputElement;
      fireEvent.change(phone, { target: { value: "555-0100" } });
      fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
      await waitFor(() => expect(h.update).toHaveBeenCalled(), {
        timeout: 10000,
      });
      const [, body] = h.update.mock.calls[0];
      expect(body).toEqual({ contact_phone: "555-0100" });
    });

    it("an untouched Save sends no request", async () => {
      h.rows = [BASE, { ...BASE }];
      renderPage();
      await screen.findByText("Cogent", {}, { timeout: 10000 });
      fireEvent.click(screen.getByTitle("Edit"));
      await screen.findByDisplayValue("ACC-1", {}, { timeout: 10000 });
      fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
      await new Promise((r) => setTimeout(r, 50));
      expect(h.update).not.toHaveBeenCalled();
    });
  },
);
