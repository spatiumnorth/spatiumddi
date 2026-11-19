/**
 * @vitest-environment jsdom
 *
 * A server row's detail dialog opens from the keyboard too (#2724): the
 * row's click opened it, and nothing a keyboard reaches did.
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
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
/** Per API object, the calls a test answers. Anything else stays pending. */
const answers: Record<string, Record<string, Answer>> = {};

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
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { DNSPage } = await import("@/pages/dns/DNSPage");
const { DHCPPage } = await import("@/pages/dhcp/DHCPPage");

const STAMP = "2026-10-03T00:00:00Z";

function show(ui: ReactNode, url: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  for (const k of Object.keys(answers)) delete answers[k];
  localStorage.clear();
  sessionStorage.clear();
});

const DNS_GROUP = {
  id: "grp-1",
  name: "g",
  description: "",
  group_type: "internal",
  default_view: null,
  is_recursive: false,
  catalog_zones_enabled: false,
  catalog_zone_name: "",
  server_drivers: [],
  created_at: STAMP,
  modified_at: STAMP,
};
const DNS_SERVER = {
  id: "s1",
  group_id: "grp-1",
  name: "ns-one",
  driver: "bind9",
  host: "10.0.0.1",
  port: 53,
  roles: [],
  status: "active",
  is_enabled: true,
  is_primary: true,
  maintenance_mode: false,
  created_at: STAMP,
  modified_at: STAMP,
};
const DHCP_GROUP = {
  id: "dgrp-1",
  name: "g",
  description: "",
  mode: "standalone",
  servers: [],
  created_at: STAMP,
  modified_at: STAMP,
};
const DHCP_SERVER = {
  id: "d1",
  server_group_id: "dgrp-1",
  name: "kea-one",
  driver: "kea",
  host: "10.0.0.2",
  port: 67,
  roles: [],
  status: "active",
  is_enabled: true,
  maintenance_mode: false,
  created_at: STAMP,
  modified_at: STAMP,
};

describe("server rows open their detail dialog from the keyboard", () => {
  it("DNS: Enter on the server's name opens ServerDetailModal", async () => {
    answers.dnsApi = {
      listGroups: async () => [DNS_GROUP],
      listServers: async () => [DNS_SERVER],
    };
    show(<DNSPage />, "/dns?group=grp-1");
    const open = await screen.findByRole("button", {
      name: "View details of ns-one",
    });
    open.focus();
    fireEvent.keyDown(open, { key: "Enter" });
    fireEvent.click(open); // a browser turns Enter on a button into a click
    await waitFor(() =>
      expect(screen.getByRole("dialog", { name: /ns-one/ })).toBeTruthy(),
    );
  });

  it("DHCP: the server's name is a button that opens the detail dialog", async () => {
    answers.dhcpApi = {
      listGroups: async () => [DHCP_GROUP],
      listServers: async () => [DHCP_SERVER],
    };
    show(<DHCPPage />, "/dhcp?group=dgrp-1");
    const open = await screen.findByRole("button", {
      name: "View details of kea-one",
    });
    fireEvent.click(open);
    await waitFor(() =>
      expect(screen.getByRole("dialog", { name: /kea-one/ })).toBeTruthy(),
    );
  });
});
