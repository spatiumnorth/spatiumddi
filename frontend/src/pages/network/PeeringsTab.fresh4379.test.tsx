/**
 * @vitest-environment jsdom
 *
 * The BGP peering Edit dialog re-reads the row when it opens and sends
 * only what the operator changed (#4379), the FreshEdit pattern #4370
 * landed for the integration dialogs. Before, it seeded once from the
 * click-time list row and always sent both relationship_type and
 * description, putting back what another client stored since the list
 * loaded.
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

function listPeerings() {
  const i = Math.min(h.reads, h.rows.length - 1);
  h.reads += 1;
  return Promise.resolve([h.rows[i]]);
}
const updatePeering = (...a: unknown[]) => {
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
    asnsApi: {
      ...actual.asnsApi,
      listPeerings,
      list: async () => ({ items: [], total: 0 }),
      updatePeering,
    },
  };
});

const { PeeringsTab } = await import("./PeeringsTab");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  h.reads = 0;
});

const BASE = {
  id: "pe1",
  local_asn_id: "asn1",
  peer_asn_id: "asn2",
  peer_asn_number: 65001,
  peer_asn_name: "Peer One",
  local_asn_number: 65000,
  local_asn_name: "Local",
  relationship_type: "peer",
  description: "old description",
};

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <PeeringsTab asnId="asn1" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe(
  "BGP peering Edit dialog re-reads the row (#4379)",
  { timeout: 30000 },
  () => {
    it("shows the fresh values, not the click-time row", async () => {
      h.rows = [
        BASE,
        { ...BASE, relationship_type: "customer", description: "new desc" },
      ];
      renderTab();
      await screen.findByText("AS65001 — Peer One", {}, { timeout: 10000 });
      fireEvent.click(screen.getByTitle("Edit"));
      const desc = await screen.findByDisplayValue(
        "new desc",
        {},
        { timeout: 10000 },
      );
      expect(desc).toBeTruthy();
      const checked = document.querySelector(
        'input[name="relationship"]:checked',
      ) as HTMLInputElement;
      expect(checked.closest("label")?.textContent).toContain("customer");
    });

    it("an unrelated Save sends only the changed field", async () => {
      h.rows = [
        BASE,
        { ...BASE, relationship_type: "customer", description: "new desc" },
      ];
      renderTab();
      await screen.findByText("AS65001 — Peer One", {}, { timeout: 10000 });
      fireEvent.click(screen.getByTitle("Edit"));
      const desc = await screen.findByDisplayValue(
        "new desc",
        {},
        { timeout: 10000 },
      );
      fireEvent.change(desc, { target: { value: "touched" } });
      fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
      await waitFor(() => expect(h.update).toHaveBeenCalled(), {
        timeout: 10000,
      });
      const [, body] = h.update.mock.calls[0];
      expect(body).toEqual({ description: "touched" });
    });

    it("an untouched Save sends no request", async () => {
      h.rows = [BASE, { ...BASE }];
      renderTab();
      await screen.findByText("AS65001 — Peer One", {}, { timeout: 10000 });
      fireEvent.click(screen.getByTitle("Edit"));
      await screen.findByDisplayValue(
        "old description",
        {},
        { timeout: 10000 },
      );
      fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
      await new Promise((r) => setTimeout(r, 50));
      expect(h.update).not.toHaveBeenCalled();
    });
  },
);
