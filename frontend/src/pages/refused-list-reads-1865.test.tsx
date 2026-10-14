/**
 * @vitest-environment jsdom
 *
 * A list a scoped user may not read is never shown to them as empty (#1865).
 *
 * #1343 taught eight surfaces to say so; every other list page rendered
 * `data ?? []` and told a user holding narrower roles "No audit events
 * found", "No policies yet", "No VRFs yet." over lists that held rows. These
 * render a sample of those pages with the list read refused the way the API
 * refuses it, and hold each to saying so; a control per page shows an empty
 * list still reads as empty.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";

function refusal(detail: string) {
  return Object.assign(new Error("Request failed with status code 403"), {
    isAxiosError: true,
    status: 403,
    response: { status: 403, data: { detail } },
  });
}

const lists = {
  audit: vi.fn(),
  policies: vi.fn(),
  vrfs: vi.fn(),
  requests: vi.fn(),
  clusters: vi.fn(),
  feeds: vi.fn(),
  asns: vi.fn(),
  devices: vi.fn(),
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    auditApi: { ...actual.auditApi, list: () => lists.audit() },
    conformityApi: {
      ...actual.conformityApi,
      listPolicies: () => lists.policies(),
    },
    vrfsApi: { ...actual.vrfsApi, list: () => lists.vrfs() },
    requestsApi: { ...actual.requestsApi, list: () => lists.requests() },
    kubernetesApi: {
      ...actual.kubernetesApi,
      listClusters: () => lists.clusters(),
    },
    firewallFeedsApi: {
      ...actual.firewallFeedsApi,
      list: () => lists.feeds(),
    },
    asnsApi: { ...actual.asnsApi, list: () => lists.asns() },
    networkApi: {
      ...actual.networkApi,
      listDevices: () => lists.devices(),
    },
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { AuditPage } = await import("@/pages/admin/AuditPage");
const { ConformityPage } = await import("@/pages/admin/ConformityPage");
const { VRFsPage } = await import("@/pages/vrfs/VRFsPage");
const { default: RequestsPage } = await import("@/pages/RequestsPage");
const { KubernetesPage } = await import("@/pages/kubernetes/KubernetesPage");
const { FirewallFeedsPage } =
  await import("@/pages/firewall_feeds/FirewallFeedsPage");
const { AsnsPage } = await import("@/pages/network/AsnsPage");
const { NetworkPage } = await import("@/pages/network/NetworkPage");

function show(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  for (const fn of Object.values(lists)) fn.mockReset();
});

// `count` is the page's row counter where it has one: a refused read is not
// "0 total" any more than it is "No VRFs yet." (the QA check names both).
const REFUSED: {
  name: string;
  page: () => ReactNode;
  fn: (typeof lists)[keyof typeof lists];
  what: RegExp;
  empty: RegExp;
  count?: RegExp;
  none: unknown;
}[] = [
  {
    name: "Audit Log",
    page: () => <AuditPage />,
    fn: lists.audit,
    what: /the audit log/,
    empty: /No audit events found/,
    count: /0 events/,
    none: { items: [], total: 0 },
  },
  {
    name: "Conformity",
    page: () => <ConformityPage />,
    fn: lists.policies,
    what: /conformity policies/,
    empty: /No policies yet/,
    none: [],
  },
  {
    name: "VRFs",
    page: () => <VRFsPage />,
    fn: lists.vrfs,
    what: /VRFs/,
    empty: /No VRFs yet/,
    count: /0 total/,
    none: [],
  },
  {
    name: "Requests",
    page: () => <RequestsPage />,
    fn: lists.requests,
    what: /requests/,
    empty: /No requests/,
    none: [],
  },
  {
    name: "Kubernetes",
    page: () => <KubernetesPage />,
    fn: lists.clusters,
    what: /Kubernetes clusters/,
    empty: /No clusters configured yet/,
    none: [],
  },
  {
    name: "Firewall feeds",
    page: () => <FirewallFeedsPage />,
    fn: lists.feeds,
    what: /firewall feeds/,
    empty: /No firewall feeds yet/,
    none: [],
  },
  {
    name: "ASNs",
    page: () => <AsnsPage />,
    fn: lists.asns,
    what: /ASNs/,
    empty: /No ASNs tracked yet/,
    count: /0 ASNs/,
    none: { items: [], total: 0 },
  },
  {
    name: "Network devices",
    page: () => <NetworkPage />,
    fn: lists.devices,
    what: /network devices/,
    empty: /No network devices yet/,
    none: { items: [], total: 0 },
  },
];

describe("a refused list read says so instead of showing the empty state", () => {
  for (const c of REFUSED) {
    it(c.name, async () => {
      c.fn.mockRejectedValue(refusal("Permission denied: need 'read'"));
      show(c.page());
      await screen.findByText(
        new RegExp(`You don't have permission to see ${c.what.source}`),
      );
      expect(screen.queryByText(c.empty)).toBeNull();
      if (c.count) expect(screen.queryByText(c.count)).toBeNull();
    });
  }
});

describe("a list that really is empty still says so (control)", () => {
  for (const c of REFUSED) {
    it(c.name, async () => {
      c.fn.mockResolvedValue(c.none);
      show(c.page());
      await screen.findByText(c.empty);
      expect(screen.queryByText(/permission to see/)).toBeNull();
      if (c.count) expect(screen.getByText(c.count)).toBeTruthy();
    });
  }
});

it("Audit Log offers no PDF export to a reader refused the log", async () => {
  lists.audit.mockRejectedValue(refusal("Permission denied: need 'read'"));
  show(<AuditPage />);
  await screen.findByText(/You don't have permission to see the audit log/);
  expect(
    (screen.getByRole("button", { name: /Export PDF/ }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);
});
