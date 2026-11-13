/**
 * @vitest-environment jsdom
 *
 * A list the Requester may not read is never drawn as empty (#3836): New
 * device watch, Compliance, Custom fields, NAT, Subnet planner, Sites (tree
 * view) and VLANs say the read was refused, in words.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

function refused() {
  return Object.assign(new Error("Request failed with status code 403"), {
    isAxiosError: true,
    response: { status: 403, data: { detail: "Permission denied" } },
  });
}

// Every API method the pages call is refused (403), as for a Requester.
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
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
                : () => Promise.reject(refused()),
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
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { NewDevicesPage } = await import("@/pages/security/NewDevicesPage");
const { CompliancePage } = await import("@/pages/admin/CompliancePage");
const { CustomFieldsPage } = await import("@/pages/admin/CustomFieldsPage");
const { NATPage } = await import("@/pages/ipam/NATPage");
const { SubnetPlannerListPage } =
  await import("@/pages/ipam/SubnetPlannerListPage");
const { SitesPage } = await import("@/pages/network/SitesPage");
const { VLANsPage } = await import("@/pages/vlans/VLANsPage");

function open(page: React.ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{page}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  try {
    sessionStorage.clear();
  } catch {
    // jsdom without storage: nothing was kept to clear.
  }
});

const cases: [string, () => React.ReactElement, RegExp, RegExp][] = [
  [
    "New device watch",
    () => <NewDevicesPage />,
    /don't have permission to see sightings/,
    /No sightings match/,
  ],
  [
    "Compliance",
    () => <CompliancePage />,
    /don't have permission to see subnets/,
    /No subnets tagged/,
  ],
  [
    "Custom fields",
    () => <CustomFieldsPage />,
    /don't have permission to see custom fields/,
    /No custom fields defined yet/,
  ],
  [
    "NAT",
    () => <NATPage />,
    /don't have permission to see NAT mappings/,
    /No NAT mappings match/,
  ],
  [
    "Subnet planner",
    () => <SubnetPlannerListPage />,
    /don't have permission to see plans/,
    /No plans yet/,
  ],
  [
    "Sites",
    () => <SitesPage />,
    /don't have permission to see sites/,
    /No sites yet/,
  ],
  [
    "VLANs",
    () => <VLANsPage />,
    /don't have permission to see routers/,
    /No routers yet/,
  ],
];

describe("a refused list is not drawn as empty (#3836)", () => {
  for (const [name, page, said, empty] of cases) {
    it(name, async () => {
      sessionStorage.setItem("sites-view", "tree");
      open(page());
      expect((await screen.findAllByText(said)).length).toBeGreaterThan(0);
      expect(screen.queryByText(empty)).toBeNull();
    });
  }
});
