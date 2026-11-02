/**
 * @vitest-environment jsdom
 *
 * A search or filter that matches nothing on an E911 list that holds rows
 * says so, not "No X yet" (#2800, the gap #2616's fix left).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const lists = { erls: vi.fn(), bindings: vi.fn() };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    e911Api: {
      ...actual.e911Api,
      listErls: (p: unknown) => lists.erls(p),
      listBindings: (p: unknown) => lists.bindings(p),
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
      can: () => false,
      isSuperadmin: false,
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

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <E911Page />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  lists.erls.mockReset();
  lists.bindings.mockReset();
});

describe("E911 lists", () => {
  it("Locations: a really empty list still says yet", async () => {
    lists.erls.mockResolvedValue({ items: [], total: 0, limit: 50, offset: 0 });
    show();
    await screen.findByText(/No Emergency Response Locations yet/);
  });

  it("Locations: a search with no hits says it matched nothing", async () => {
    lists.erls.mockImplementation((p: { q?: string }) =>
      Promise.resolve({
        items: p.q ? [] : [erl],
        total: p.q ? 0 : 1,
        limit: 50,
        offset: 0,
      }),
    );
    show();
    await screen.findByText("HQ Lobby");
    fireEvent.change(screen.getByPlaceholderText(/Name, building, floor/), {
      target: { value: "zzz" },
    });
    await screen.findByText(
      /No Emergency Response Locations match the current search or filter/,
    );
    expect(
      screen.queryByText(/No Emergency Response Locations yet/),
    ).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    await screen.findByText("HQ Lobby");
  });

  it("Bindings: a rule-kind filter with no hits says it matched nothing", async () => {
    lists.erls.mockResolvedValue({ items: [], total: 0, limit: 50, offset: 0 });
    lists.bindings.mockImplementation((p: { rule_kind?: string }) =>
      Promise.resolve({
        items: p.rule_kind ? [] : [binding],
        total: p.rule_kind ? 0 : 1,
        limit: 50,
        offset: 0,
      }),
    );
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Bindings" }));
    await screen.findByText("HQ Lobby");
    fireEvent.change(screen.getByDisplayValue("All rule kinds"), {
      target: { value: "mac" },
    });
    await screen.findByText(
      /No location bindings match the current search or filter/,
    );
    expect(screen.queryByText(/No bindings yet/)).toBeNull();
  });
});
