/**
 * @vitest-environment jsdom
 *
 * The IPAM tree's BGP chip asked GET /looking-glass/routes of every user who
 * opened a space with the Looking Glass module on, whatever their grants. A
 * user who may not read the Looking Glass (the IPAM, DNS and DHCP Editors)
 * was refused once per space, each refusal a console error and a `denied`
 * audit row (#2745, the class of #2704). The route search is now asked only
 * with read on 'bgp_lg_peer', the grant the route takes.
 */
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { BGPLGRoute } from "@/lib/api";

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

// The Looking Glass module is on: the chip's only gate before this fix.
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

const { BgpAdvertisedChip } = await import("./bgp-lg-chips");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function signInAs(grants: [string, string][]) {
  const myPermissions = vi.fn(() =>
    Promise.resolve({
      is_superadmin: false,
      grants: grants.map(([action, resource_type]) => ({
        action,
        resource_type,
        resource_id: null,
      })),
    }),
  );
  answers.authApi = { myPermissions };
  return myPermissions;
}

function spyRouteSearch(items: BGPLGRoute[]) {
  const searchRoutes = vi.fn(() =>
    Promise.resolve({ items, total: items.length }),
  );
  answers.lookingGlassApi = { searchRoutes };
  return searchRoutes;
}

/** A space's block row and one of its subnet rows, as the IPAM tree renders
 *  them: both chips share the one space-scoped route search. */
function openSpace() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrap = (node: ReactNode) => (
    <QueryClientProvider client={qc}>{node}</QueryClientProvider>
  );
  render(
    wrap(
      <>
        <BgpAdvertisedChip spaceId="sp1" blockId="b1" />
        <BgpAdvertisedChip spaceId="sp1" subnetId="s1" />
      </>,
    ),
  );
}

const ROUTE = {
  id: "r1",
  prefix: "10.71.1.0/24",
  matched_subnet_id: "s1",
  matched_block_id: null,
  rpki_status: "valid",
} as unknown as BGPLGRoute;

describe("IPAM tree BGP chip", () => {
  it("sends no route search for a user who may not read the Looking Glass", async () => {
    // The IPAM, DNS and DHCP Editors' grants: none is on 'bgp_lg_peer'.
    const myPermissions = signInAs([
      ["admin", "ip_space"],
      ["admin", "ip_block"],
      ["admin", "subnet"],
      ["admin", "ip_address"],
      ["admin", "dns_zone"],
      ["admin", "dhcp_scope"],
    ]);
    const searchRoutes = spyRouteSearch([ROUTE]);
    openSpace();
    // Let the grants arrive: the search may only follow them.
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(searchRoutes).not.toHaveBeenCalled();
    expect(myPermissions).toHaveBeenCalled();
    expect(screen.queryByText("BGP")).toBeNull();
  });

  it("asks the space's route search once for a user who may read it, and shows the chip", async () => {
    signInAs([["read", "bgp_lg_peer"]]);
    const searchRoutes = spyRouteSearch([ROUTE]);
    openSpace();
    await screen.findByText("BGP");
    expect(searchRoutes).toHaveBeenCalledTimes(1);
    expect(searchRoutes).toHaveBeenCalledWith({
      matched_space_id: "sp1",
      withdrawn: false,
      limit: 1000,
    });
  });
});
