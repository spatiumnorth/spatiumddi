/**
 * @vitest-environment jsdom
 *
 * Walking one's own space and address asked reads the IPAM, DNS and DHCP
 * Editors may not make (each a 403 and a `denied` audit row), and a space
 * linked to a VRF read "VRF / BGP — not configured" over the refused VRF
 * list (#2704). Each read is now asked only with its grant, and the space's
 * VRF line says it is linked but not shown.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { IPAddress, IPSpace } from "@/lib/api";

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

const { IPDetailModal } = await import("./IPDetailModal");
const { SpaceVrfBadges } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function signInAs(grants: [string, string][]) {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve({
        is_superadmin: false,
        grants: grants.map(([action, resource_type]) => ({
          action,
          resource_type,
          resource_id: null,
        })),
      }),
  };
}

function wrap(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const STAMP = "2026-10-22T00:00:00Z";
const ADDR = {
  id: "a1",
  subnet_id: "s1",
  address: "10.71.1.10",
  status: "allocated",
  role: null,
  hostname: "h",
  fqdn: null,
  description: "",
  mac_address: null,
  tags: {},
  custom_fields: {},
  created_at: STAMP,
  modified_at: STAMP,
} as unknown as IPAddress;

const READS: [string, string, string][] = [
  ["bacnetApi", "byAddress", "bacnet_device"],
  ["dicomApi", "byAddress", "dicom_ae"],
  ["otApi", "byAddress", "ot_device"],
  ["multicastApi", "listMembershipsByIP", "multicast"],
  ["lookingGlassApi", "routeForIp", "bgp_lg_peer"],
  ["tlsCertsApi", "list", "tls_cert"],
  ["dnsblApi", "byIp", "dnsbl"],
];

function spyAll() {
  const spies: Record<string, ReturnType<typeof vi.fn>> = {};
  for (const [api, method] of READS) {
    const fn = vi.fn(() =>
      Promise.reject({
        response: { status: 403, data: { detail: "need 'read'" } },
      }),
    );
    spies[`${api}.${method}`] = fn;
    answers[api] = { ...(answers[api] ?? {}), [method]: fn };
  }
  return spies;
}

function openDetail() {
  wrap(
    <IPDetailModal
      address={ADDR}
      canEdit={false}
      onClose={() => {}}
      onEdit={() => {}}
      onScan={() => {}}
    />,
  );
}

describe("IP detail reads", () => {
  it("asks none of the registry reads a user without the grants", async () => {
    signInAs([["read", "ip_address"]]);
    const spies = spyAll();
    openDetail();
    await waitFor(() =>
      expect(document.body.textContent).toContain(
        "You don't have permission to see this IP's blocklist status",
      ),
    );
    await new Promise((r) => setTimeout(r, 50));
    for (const [k, fn] of Object.entries(spies))
      expect([k, fn.mock.calls.length]).toEqual([k, 0]);
    expect(document.body.textContent).not.toContain(
      "No blocklists are enabled",
    );
  });

  it("still asks each read for a user holding the grants", async () => {
    signInAs(READS.map(([, , res]) => ["read", res] as [string, string]));
    const spies = spyAll();
    openDetail();
    await waitFor(() => {
      for (const [k, fn] of Object.entries(spies))
        expect([k, fn.mock.calls.length > 0]).toEqual([k, true]);
    });
  });
});

const SPACE = {
  id: "sp1",
  name: "lab",
  vrf_id: "v1",
  vrf_name: null,
  route_distinguisher: null,
  route_targets: null,
  asn_id: null,
} as unknown as IPSpace;

describe("Space VRF line", () => {
  it("says the VRF is linked but not shown, and does not ask for the list", async () => {
    signInAs([["read", "ip_space"]]);
    const list = vi.fn(() => Promise.reject({ response: { status: 403 } }));
    answers.vrfsApi = { list };
    wrap(<SpaceVrfBadges space={SPACE} />);
    await waitFor(() =>
      expect(document.body.textContent).toContain("linked, not shown"),
    );
    expect(document.body.textContent).not.toContain("not configured");
    expect(list).not.toHaveBeenCalled();
  });

  it("names the VRF for a user who may read VRFs", async () => {
    signInAs([["read", "vrf"]]);
    answers.vrfsApi = {
      list: () =>
        Promise.resolve([
          {
            id: "v1",
            name: "CUST-A",
            route_distinguisher: "65000:1",
            import_targets: [],
            export_targets: [],
          },
        ]),
    };
    wrap(<SpaceVrfBadges space={SPACE} />);
    await waitFor(() =>
      expect(document.body.textContent).toContain("VRF: CUST-A"),
    );
  });
});
