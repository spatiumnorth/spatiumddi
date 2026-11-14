/**
 * @vitest-environment jsdom
 *
 * A read-only reader is not told to use a control the page disables (#4116,
 * the rest of #3885).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
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

const { NmapToolsPage } = await import("./nmap/NmapToolsPage");
const { PacketCapturePage } = await import("./pcap/PacketCapturePage");
const { SubnetPlannerListPage } = await import("./ipam/SubnetPlannerListPage");
const { DriftView } = await import("./dns/DriftView");

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

const cases: Array<[string, () => ReactElement, () => void, RegExp, string]> = [
  [
    "Nmap History",
    () => <NmapToolsPage />,
    () => {
      answers.nmapApi = { listScans: async () => ({ items: [], total: 0 }) };
    },
    /No scans yet/,
    "kick one off",
  ],
  [
    "Packet Capture History",
    () => <PacketCapturePage />,
    () => {
      answers.pcapApi = {
        listCaptures: async () => ({ items: [], total: 0 }),
      };
    },
    /No captures yet/,
    "start one",
  ],
  [
    "Subnet Plans",
    () => <SubnetPlannerListPage />,
    () => {
      answers.ipamApi = { listSubnetPlans: async () => [] };
    },
    /No plans yet/,
    "design a CIDR hierarchy",
  ],
  [
    "Drift",
    () => (
      <DriftView
        group={{ id: "g" } as never}
        zone={{ id: "z", name: "example.com." } as never}
      />
    ),
    () => {
      answers.dnsApi = {
        getZoneDrift: async () => ({ db_record_count: 1, servers: [] }),
      };
    },
    /Read-only — nothing here is applied/,
    "Use Sync",
  ],
];

describe("instruction sentences follow the control's gate (#4116)", () => {
  for (const [name, ui, setup, lead, hint] of cases) {
    it(`${name}: a reader without write is not told to use the control`, async () => {
      writer = false;
      setup();
      mount(ui());
      const el = await screen.findByText(lead);
      await waitFor(() => expect(el.textContent).not.toContain(hint));
      expect(document.body.textContent).not.toContain(hint);
    });

    it(`${name}: a writer is told`, async () => {
      writer = true;
      setup();
      mount(ui());
      await screen.findByText(lead);
      expect(document.body.textContent).toContain(hint);
    });
  }
});
