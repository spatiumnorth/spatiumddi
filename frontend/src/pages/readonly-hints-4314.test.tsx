/**
 * @vitest-environment jsdom
 *
 * A read-only reader is not told to use a control the page disables (#4314,
 * the pages #4116 did not list).
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
import type { ReactElement } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
let writer = false;

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
      can: (action: string) => writer || action === "read",
      isSuperadmin: writer,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { OTDevicesPage } = await import("./network/OTDevicesPage");
const { AVFlowsPage } = await import("./network/AVFlowsPage");
const { DhcpAuditTab } = await import("./LogsPage");
const { WakeSchedulesPage } = await import("./tools/WakeSchedulesPage");
const { ConformityPage } = await import("./admin/ConformityPage");
const { DNSSECPoliciesPage } = await import("./dns/DNSSECPoliciesPage");
const { NetworkPage } = await import("./network/NetworkPage");
const { AsnsPage } = await import("./network/AsnsPage");
const { ResultTab } = await import("./pcap/PacketCapturePage");
const { DhcpPoolPressure, AsnSummaryCard, VrfSummaryCard, DomainsSummaryCard } =
  await import("./DashboardPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function mount(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const none = async () => ({ items: [], total: 0 });
const empty = async () => [];

// [name, ui, setup, lead sentence, instruction only a writer is told, after-mount step]
const cases: Array<
  [string, () => ReactElement, () => void, RegExp, string, (() => void)?]
> = [
  [
    "OT Devices",
    () => <OTDevicesPage />,
    () => {
      answers.otApi = { listDevices: none };
    },
    /No OT descriptors recorded/,
    "Attach one to an existing IPAM address",
  ],
  [
    "AV over IP",
    () => <AVFlowsPage />,
    () => {
      answers.avApi = { listFlows: none };
    },
    /No AV flows recorded/,
    "Stamp a multicast group",
  ],
  [
    "Logs DHCP Audit",
    () => <DhcpAuditTab sources={[]} />,
    () => {},
    /DHCP audit logs require a Windows DHCP server/,
    "Register one under DHCP",
  ],
  [
    "Wake Schedules Calendars",
    () => <WakeSchedulesPage />,
    () => {
      answers.wakeSchedulesApi = { list: empty, listCalendars: empty };
    },
    /No calendars subscribed yet/,
    "so a schedule can skip holidays",
    () => fireEvent.click(screen.getAllByText("Calendars")[0]),
  ],
  [
    "Wake Schedules",
    () => <WakeSchedulesPage />,
    () => {
      answers.wakeSchedulesApi = { list: empty, listCalendars: empty };
    },
    /No wake schedules yet/,
    "Create one to wake a tagged fleet",
  ],
  [
    "Conformity results",
    () => <ConformityPage />,
    () => {
      answers.conformityApi = {
        listPolicies: empty,
        listResults: empty,
        listCheckKinds: empty,
      };
    },
    /No results match the current filter/,
    "Re-evaluate a policy",
  ],
  [
    "Conformity intro",
    () => <ConformityPage />,
    () => {
      answers.conformityApi = {
        listPolicies: empty,
        listResults: empty,
        listCheckKinds: empty,
      };
    },
    /Built-in policies are seeded disabled/,
    "Toggle them on to start collecting evidence",
  ],
  [
    "DNSSEC Policies",
    () => <DNSSECPoliciesPage />,
    () => {
      answers.dnsApi = { listDnssecPolicies: empty };
    },
    /Reusable BIND9 signing policies/,
    "Attach one to a zone from its DNSSEC card",
  ],
  [
    "Network devices",
    () => <NetworkPage />,
    () => {
      answers.networkApi = { listDevices: none };
    },
    /No network devices yet/,
    "Add a router or switch",
  ],
  [
    "ASNs",
    () => <AsnsPage />,
    () => {
      answers.asnsApi = { list: none };
    },
    /No ASNs tracked yet/,
    "Add one to start the registry",
  ],
  [
    "Packet Capture Result",
    () => <ResultTab captureId={null} />,
    () => {},
    /Nothing to show yet/,
    "run a capture",
  ],
  [
    "Dashboard DHCP pools",
    () => <DhcpPoolPressure dhcpOn />,
    () => {
      answers.dhcpApi = {
        fleetPoolOccupancy: async () => ({ pool_count: 0, pools: [] }),
      };
    },
    /No dynamic DHCP pools configured/,
    "Add a pool to a scope",
  ],
  [
    "Dashboard ASN card",
    () => <AsnSummaryCard />,
    () => {
      answers.asnsApi = { list: none };
    },
    /No ASNs configured/,
    "Add one",
  ],
  [
    "Dashboard VRF card",
    () => <VrfSummaryCard />,
    () => {
      answers.vrfsApi = { list: empty };
    },
    /No VRFs configured/,
    "Add one",
  ],
  [
    "Dashboard domains card",
    () => <DomainsSummaryCard />,
    () => {
      answers.domainsApi = { list: none };
    },
    /No domains configured/,
    "Add one",
  ],
];

describe("instruction sentences follow the control's gate (#4314)", () => {
  for (const [name, ui, setup, lead, hint, step] of cases) {
    it(`${name}: a reader without write is not told to use the control`, async () => {
      writer = false;
      setup();
      mount(ui());
      step?.();
      const el = await screen.findByText(lead);
      await waitFor(() => expect(el.textContent).not.toContain(hint));
      expect(document.body.textContent).not.toContain(hint);
    });

    it(`${name}: a writer is told`, async () => {
      writer = true;
      setup();
      mount(ui());
      step?.();
      await screen.findByText(lead);
      expect(document.body.textContent).toContain(hint);
    });
  }
});
