/**
 * @vitest-environment jsdom
 *
 * Edit Subnet for a holder whose grant names one subnet (#3904): the router,
 * VLAN and site lists are reads that grant lacks, so each picker keeps the
 * link the subnet's own row carries instead of drawing "None" over it.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { Subnet } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
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

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    modules: [],
    ready: true,
    isLoading: false,
    isError: false,
    refetch: () => {},
    enabled: () => true,
  }),
}));

const { EditSubnetModal } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const refused = () =>
  Promise.reject(
    Object.assign(new Error("forbidden"), {
      response: { status: 403, data: { detail: "Permission denied" } },
    }),
  );

const subnet = {
  id: "sub-1",
  space_id: "sp-1",
  block_id: "blk-1",
  network: "10.1.0.0/24",
  name: "lab",
  description: "",
  total_ips: 254,
  allocated_ips: 0,
  utilization_percent: 0,
  dns_group_ids: [],
  tags: {},
  custom_fields: {},
  vlan_ref_id: "vlan-1",
  vlan: {
    id: "vlan-1",
    router_id: "rt-1",
    router_name: "core-rtr",
    vlan_id: 3123,
    name: "lab-vlan",
  },
  customer_id: "cust-1",
  site_id: "site-1",
} as unknown as Subnet;

describe("Edit Subnet for a subnet-scoped writer (#3904)", () => {
  it("shows the router, VLAN and site the subnet carries, not None", async () => {
    answers.authApi = {
      myPermissions: () =>
        Promise.resolve({
          is_superadmin: false,
          grants: [
            { action: "read", resource_type: "subnet", resource_id: "sub-1" },
            { action: "write", resource_type: "subnet", resource_id: "sub-1" },
          ],
        }),
    };
    answers.ipamApi = { getSubnet: () => Promise.resolve(subnet) };
    answers.vlansApi = {
      listRouters: refused,
      getVlan: refused,
      listVlans: refused,
    };
    answers.sitesApi = { list: refused };
    answers.customersApi = { list: refused };
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <EditSubnetModal
            subnet={subnet}
            onClose={() => {}}
            onDeleted={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const shown = () =>
      screen
        .queryAllByRole("combobox")
        .map(
          (el) =>
            (el as HTMLSelectElement).selectedOptions[0]?.textContent ?? "",
        );
    await waitFor(() => expect(shown()).toContain("(current site)"));
    expect(shown()).toContain("core-rtr");
    expect(shown()).toContain("3123 — lab-vlan");
    expect(shown()).toContain("(current site)");
    const vlan = screen
      .getAllByRole("combobox")
      .find(
        (el) =>
          (el as HTMLSelectElement).selectedOptions[0]?.textContent ===
          "3123 — lab-vlan",
      ) as HTMLSelectElement;
    expect(vlan.disabled).toBe(false);
  });
});
