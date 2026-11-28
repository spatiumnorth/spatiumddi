/**
 * @vitest-environment jsdom
 *
 * A refused delete of an E911 location or binding keeps its confirm open and
 * says why inside it, announced (#4218): the page's own line sits behind the
 * aria-modal dialog, which a screen reader treats as inert.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const refuse = (status: number, detail: string) =>
  Object.assign(new Error(String(status)), {
    response: { status, data: { detail } },
  });

const api = {
  listErls: vi.fn(),
  listBindings: vi.fn(),
  removeErl: vi.fn(),
  removeBinding: vi.fn(),
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    e911Api: {
      ...actual.e911Api,
      listErls: (p: unknown) => api.listErls(p),
      listBindings: (p: unknown) => api.listBindings(p),
      removeErl: (id: string) => api.removeErl(id),
      removeBinding: (id: string) => api.removeBinding(id),
    },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      canExplicit: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

const { E911Page } = await import("@/pages/network/E911Page");

const erl = {
  id: "e1",
  name: "HQ Lobby",
  site_id: null,
  elins: [],
  validation_state: "validated",
  validated_at: null,
  validation_source: null,
  validation_detail: null,
  is_dispatchable: true,
  is_active: true,
  notes: "",
  binding_count: 0,
  created_at: "",
  modified_at: "",
};
const binding = {
  id: "b1",
  erl_id: "e1",
  erl_name: "HQ Lobby",
  rule_kind: "subnet",
  precedence: 1,
  network_interface_id: null,
  bssid: null,
  subnet_id: null,
  vlan_ref_id: null,
  mac_address: null,
  ip_address_id: null,
  site_id: null,
  is_active: true,
  notes: "",
  created_at: "",
  modified_at: "",
};
const page = (items: unknown[]) => ({ items, total: 1, limit: 50, offset: 0 });

function show(tab?: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[tab ? `/?tab=${tab}` : "/"]}>
        <E911Page />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  Object.values(api).forEach((m) => m.mockReset());
});

describe("a refused E911 delete (#4218)", () => {
  it("a location's confirm stays open and announces why", async () => {
    api.listErls.mockResolvedValue(page([erl]));
    api.listBindings.mockResolvedValue(page([]));
    api.removeErl.mockRejectedValue(refuse(404, "ERL not found"));
    show();
    fireEvent.click(await screen.findByTitle("Delete"));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    const alert = await within(dialog).findByRole("alert");
    expect(alert.textContent).toContain("ERL not found");
  });

  it("a binding's confirm stays open and announces why", async () => {
    api.listErls.mockResolvedValue(page([]));
    api.listBindings.mockResolvedValue(page([binding]));
    api.removeBinding.mockRejectedValue(refuse(404, "Binding not found"));
    show();
    fireEvent.click(await screen.findByRole("button", { name: /Bindings/ }));
    fireEvent.click(await screen.findByTitle("Delete"));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(within(dialog).getByRole("alert").textContent).toContain(
        "Binding not found",
      ),
    );
  });
});
