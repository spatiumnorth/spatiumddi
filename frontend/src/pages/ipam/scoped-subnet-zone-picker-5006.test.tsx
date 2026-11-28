/**
 * @vitest-environment jsdom
 *
 * Edit Subnet's DNS tab for a writer scoped to one subnet and one zone
 * (#5006). The group list and the group's zone list are refused to that
 * role; the picker is fed from the subnet's writable-zones instead, and a
 * viewer with no write sees no picker.
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
import type { Subnet } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
const calls: Record<string, unknown[][]> = {};
let grants: [string, string, string | null][] = [];

const refused = () =>
  Promise.reject(
    Object.assign(new Error("forbidden"), {
      response: { status: 403, data: { detail: "Permission denied" } },
    }),
  );

const stored = () => ({
  id: "sn-1",
  space_id: "sp-1",
  block_id: "b-1",
  network: "10.73.5.0/24",
  utilization_percent: 0,
  allocated_ips: 0,
  total_ips: 254,
  dns_inherit_settings: false,
  dns_group_ids: ["g1"],
  dns_zone_id: null,
  dns_additional_zone_ids: [],
});

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
                : (...args: unknown[]) => {
                    (calls[`${name}.${String(method)}`] ??= []).push(args);
                    return (answers[name]?.[method as string] ?? pending)(
                      ...args,
                    );
                  },
          },
        ),
      ]),
  );
  // listZones keeps its real 403 -> writable-zones fallback (api.ts); only
  // the HTTP layer under it is faked, so the picker is fed the way it is live.
  return { ...actual, ...stubs, dnsApi: actual.dnsApi };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { EditSubnetModal } = await import("./IPAMPage");
const { api } = await import("@/lib/api");

const original = api.defaults.adapter;
const urls: string[] = [];
afterEach(() => {
  cleanup();
  api.defaults.adapter = original;
  urls.length = 0;
  for (const k of Object.keys(answers)) delete answers[k];
  for (const k of Object.keys(calls)) delete calls[k];
});

function serve() {
  api.defaults.adapter = async (config) => {
    urls.push(config.url ?? "");
    const reply = (data: unknown, status: number) => ({
      data,
      status,
      statusText: "",
      headers: {},
      config,
    });
    if (config.url === "/ipam/subnets/sn-1/writable-zones")
      return reply(
        [
          {
            id: "z1",
            name: "lab.example.",
            group_id: "g1",
            zone_type: "primary",
          },
        ],
        200,
      );
    const { AxiosError } = await import("axios");
    throw new AxiosError("x", "ERR", config, null, reply({}, 403) as never);
  };
}

function open(g: [string, string, string | null][]) {
  grants = g;
  serve();
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve({
        is_superadmin: false,
        grants: grants.map(([action, resource_type, resource_id]) => ({
          action,
          resource_type,
          resource_id,
        })),
      }),
  };
  answers.ipamApi = {
    getSubnet: () => Promise.resolve(stored()),
    getEffectiveBlockDns: refused,
    updateSubnet: (_id: unknown, body: unknown) =>
      Promise.resolve({ ...stored(), ...(body as object) }),
  };
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <EditSubnetModal
          subnet={stored() as unknown as Subnet}
          onClose={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Edit Subnet DNS tab for a subnet-scoped writer (#5006)", () => {
  it("lists the writable zone and saves it", async () => {
    open([
      ["read", "subnet", "sn-1"],
      ["write", "subnet", "sn-1"],
      ["write", "dns_zone", "z1"],
    ]);
    fireEvent.click(await screen.findByRole("button", { name: "DNS" }));
    const zone = await screen.findByLabelText("Primary Zone");
    expect(urls).toContain("/ipam/subnets/sn-1/writable-zones");
    fireEvent.change(zone, { target: { value: "z1" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(calls["ipamApi.updateSubnet"]?.[0]?.[1]).toMatchObject({
        dns_zone_id: "z1",
      }),
    );
  });

  it("offers a viewer with no write no picker", async () => {
    open([["read", "subnet", "sn-1"]]);
    fireEvent.click(await screen.findByRole("button", { name: "DNS" }));
    await screen.findByLabelText("DNS Server Group");
    await new Promise((r) => setTimeout(r, 80));
    expect(screen.queryByLabelText("Primary Zone")).toBeNull();
    expect(urls).not.toContain("/ipam/subnets/sn-1/writable-zones");
  });
});
