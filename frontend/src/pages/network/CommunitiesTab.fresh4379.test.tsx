/**
 * @vitest-environment jsdom
 *
 * The BGP community Edit dialog re-reads the row when it opens and sends
 * only what the operator changed (#4379), the same FreshEdit pattern #4370
 * landed for the integration dialogs. Before, it seeded once from the
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

const h = vi.hoisted(() => ({
  reads: 0,
  rows: [] as Record<string, unknown>[],
  update: vi.fn(),
}));

function listCommunities() {
  const i = Math.min(h.reads, h.rows.length - 1);
  h.reads += 1;
  return Promise.resolve([h.rows[i]]);
}
const updateCommunity = (...a: unknown[]) => {
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
      listCommunities,
      listStandardCommunities: async () => [],
      updateCommunity,
    },
  };
});

const { CommunitiesTab } = await import("./CommunitiesTab");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  h.reads = 0;
});

const BASE = {
  id: "c1",
  kind: "regular",
  value: "65000:100",
  name: "old name",
  description: "old description",
  inbound_action: "",
  outbound_action: "",
};

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <CommunitiesTab asnId="asn1" />
    </QueryClientProvider>,
  );
}

describe(
  "BGP community Edit dialog re-reads the row (#4379)",
  { timeout: 30000 },
  () => {
    it("shows the fresh values, not the click-time row", async () => {
      h.rows = [
        BASE,
        { ...BASE, name: "changed elsewhere", description: "new desc" },
      ];
      renderTab();
      await screen.findByText("65000:100", {}, { timeout: 10000 });
      fireEvent.click(screen.getByTitle("Edit"));
      const nameInput = await screen.findByDisplayValue(
        "changed elsewhere",
        {},
        { timeout: 10000 },
      );
      expect(nameInput).toBeTruthy();
      expect(screen.getByDisplayValue("new desc")).toBeTruthy();
    });

    it("an unrelated Save sends only the changed field", async () => {
      h.rows = [
        BASE,
        { ...BASE, name: "changed elsewhere", description: "new desc" },
      ];
      renderTab();
      await screen.findByText("65000:100", {}, { timeout: 10000 });
      fireEvent.click(screen.getByTitle("Edit"));
      const inbound = await screen.findByPlaceholderText(
        /accept|prefer/i,
        {},
        { timeout: 10000 },
      );
      fireEvent.change(inbound, { target: { value: "prefer-local" } });
      fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
      await waitFor(() => expect(h.update).toHaveBeenCalled(), {
        timeout: 10000,
      });
      const [, body] = h.update.mock.calls[0];
      expect(body).toEqual({ inbound_action: "prefer-local" });
    });

    it("an untouched Save sends no request", async () => {
      h.rows = [BASE, { ...BASE }];
      renderTab();
      await screen.findByText("65000:100", {}, { timeout: 10000 });
      fireEvent.click(screen.getByTitle("Edit"));
      await screen.findByDisplayValue("old name", {}, { timeout: 10000 });
      fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
      await new Promise((r) => setTimeout(r, 50));
      expect(h.update).not.toHaveBeenCalled();
    });
  },
);
